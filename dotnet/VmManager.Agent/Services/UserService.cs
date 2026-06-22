using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VmManager.Agent.Services.Rdp.Crypto;

namespace VmManager.Agent.Services;

public class UserService
{
    private readonly string _usersPath;
    private readonly string _credentialsPath;
    private readonly ILogger<UserService> _logger;
    private static readonly object FileLock = new object();

    private static readonly JsonSerializerOptions WriteOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly JsonSerializerOptions ReadOptions = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
    };

    public UserService(IAppPaths paths, ILogger<UserService> logger)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(logger);
        _usersPath = paths.UsersPath;
        _credentialsPath = Path.Combine(paths.AppDataDir, "api-credentials.txt");
        _logger = logger;
        EnsureAdminExists();
    }

    public List<UserAccount> GetAll()
    {
        lock (FileLock)
        {
            return LoadUsers();
        }
    }

    public UserAccount? GetByUsername(string username)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            return FindUser(users, username);
        }
    }

    private static UserAccount? FindUser(List<UserAccount> users, string identifier)
    {
        return users.FirstOrDefault(u =>
            string.Equals(u.Username, identifier, StringComparison.OrdinalIgnoreCase)
            || (
                !string.IsNullOrEmpty(u.DisplayUsername)
                && string.Equals(u.DisplayUsername, identifier, StringComparison.OrdinalIgnoreCase)
            )
        );
    }

    public UserAccount CreateUser(
        string username,
        string password,
        HashSet<string> permissions,
        bool isAdmin
    )
    {
        if (!isAdmin && !EmailValidator.IsValid(username))
            throw new InvalidOperationException(
                "Username must be a valid email address: " + username
            );

        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            CheckIdentifierAvailable(users, username, null);

            string salt = GenerateSalt();
            UserAccount account = new UserAccount
            {
                Username = username,
                Email = EmailValidator.IsValid(username) ? username : "",
                PasswordHash = HashPassword(password, salt),
                Salt = salt,
                IsAdmin = isAdmin,
                Permissions = permissions,
                CreatedAt = DateTime.UtcNow,
                MustChangePassword = !isAdmin,
                NtHash = ComputeNtHashHex(password),
            };

            users.Add(account);
            SaveUsers(users);
            _logger.LogInformation("Created user {Username} (admin={IsAdmin})", username, isAdmin);
            return account;
        }
    }

    public void DeleteUser(string username)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            int removed = users.RemoveAll(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)
            );
            if (removed == 0)
                throw new InvalidOperationException("User not found: " + username);
            SaveUsers(users);
            _logger.LogInformation("Deleted user {Username}", username);
        }
    }

    public void UpdatePermissions(string username, HashSet<string> permissions)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)
            );
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            user.Permissions = permissions;
            SaveUsers(users);
        }
    }

    public void UpdateAdmin(string username, bool isAdmin)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)
            );
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            user.IsAdmin = isAdmin;
            SaveUsers(users);
        }
    }

    public void SetMustChangePassword(string username, bool mustChange)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)
            );
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            user.MustChangePassword = mustChange;
            SaveUsers(users);
        }
    }

    public void UpdateEmail(string username, string email)
    {
        if (!string.IsNullOrWhiteSpace(email) && !EmailValidator.IsValid(email))
            throw new InvalidOperationException("Invalid email address: " + email);

        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = FindUser(users, username);
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            if (!string.IsNullOrWhiteSpace(email))
                CheckIdentifierAvailable(users, email, username);
            user.Email = email;
            SaveUsers(users);
        }
    }

    public void UpdateDisplayUsername(string username, string displayUsername)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = FindUser(users, username);
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            if (!string.IsNullOrWhiteSpace(displayUsername))
                CheckIdentifierAvailable(users, displayUsername, username);
            user.DisplayUsername = displayUsername.Trim();
            SaveUsers(users);
        }
    }

    private static void CheckIdentifierAvailable(
        List<UserAccount> users,
        string identifier,
        string? excludeUsername
    )
    {
        UserAccount? conflict = users.FirstOrDefault(u =>
            (
                excludeUsername == null
                || !string.Equals(u.Username, excludeUsername, StringComparison.OrdinalIgnoreCase)
            )
            && (
                string.Equals(u.Username, identifier, StringComparison.OrdinalIgnoreCase)
                || string.Equals(u.Email, identifier, StringComparison.OrdinalIgnoreCase)
                || string.Equals(u.DisplayUsername, identifier, StringComparison.OrdinalIgnoreCase)
            )
        );
        if (conflict != null)
            throw new InvalidOperationException("Already taken by another user: " + identifier);
    }

    public void UpdateVmCredentials(string username, string vmUsername, string vmPassword)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = FindUser(users, username);
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            user.VmUsername = vmUsername;
            user.VmPassword = vmPassword;
            SaveUsers(users);
        }
    }

    public void UpdateMaxVms(string username, int maxVms)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)
            );
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            user.MaxVms = maxVms;
            SaveUsers(users);
        }
    }

    public bool ValidateCredentials(string username, string password)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = FindUser(users, username);
            if (user == null)
            {
                _logger.LogWarning("Login failed: user not found for [{Username}]", username);
                return false;
            }
            string hash = HashPassword(password, user.Salt);
            bool valid = CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(hash),
                Encoding.UTF8.GetBytes(user.PasswordHash)
            );

            if (valid && string.IsNullOrEmpty(user.NtHash))
            {
                user.NtHash = ComputeNtHashHex(password);
                SaveUsers(users);
            }

            return valid;
        }
    }

    public void RenameUser(string oldUsername, string newUsername)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = users.FirstOrDefault(u =>
                string.Equals(u.Username, oldUsername, StringComparison.OrdinalIgnoreCase)
            );
            if (user == null)
                throw new InvalidOperationException("User not found: " + oldUsername);
            if (
                users.Any(u =>
                    string.Equals(u.Username, newUsername, StringComparison.OrdinalIgnoreCase)
                )
            )
                throw new InvalidOperationException("Username already taken: " + newUsername);
            user.Username = newUsername;
            SaveUsers(users);
            _logger.LogInformation(
                "Renamed user {OldUsername} to {NewUsername}",
                oldUsername,
                newUsername
            );
        }
    }

    public void ChangePassword(string username, string newPassword)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = FindUser(users, username);
            if (user == null)
                throw new InvalidOperationException("User not found: " + username);
            user.Salt = GenerateSalt();
            user.PasswordHash = HashPassword(newPassword, user.Salt);
            user.NtHash = ComputeNtHashHex(newPassword);
            user.MustChangePassword = false;
            SaveUsers(users);
            _logger.LogInformation("Changed password for user {Username}", username);
        }
    }

    public byte[]? GetNtHash(string username)
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            UserAccount? user = FindUser(users, username);
            if (user == null)
                return null;

            string hash = user.NtHash;
            if (string.IsNullOrEmpty(hash))
                return null;
            return Convert.FromHexString(hash);
        }
    }

    private static string ComputeNtHashHex(string password)
    {
        byte[] ntHash = Md4.ComputeNtHash(password);
        return Convert.ToHexString(ntHash).ToLowerInvariant();
    }

    private void EnsureAdminExists()
    {
        lock (FileLock)
        {
            List<UserAccount> users = LoadUsers();
            if (users.Any(u => u.IsAdmin))
                return;

            string password = GeneratePassword();
            string salt = GenerateSalt();

            UserAccount admin = new UserAccount
            {
                Username = "admin",
                PasswordHash = HashPassword(password, salt),
                Salt = salt,
                IsAdmin = true,
                Permissions = [],
                CreatedAt = DateTime.UtcNow,
                NtHash = ComputeNtHashHex(password),
            };

            users.Add(admin);
            SaveUsers(users);

            Directory.CreateDirectory(Path.GetDirectoryName(_credentialsPath)!);
            File.WriteAllText(_credentialsPath, "admin:" + password);
            _logger.LogInformation(
                "Generated admin user. Credentials written to {Path}",
                _credentialsPath
            );
        }
    }

    private List<UserAccount> LoadUsers()
    {
        if (!File.Exists(_usersPath))
            return [];

        try
        {
            string json = File.ReadAllText(_usersPath);
            return JsonSerializer.Deserialize<List<UserAccount>>(json, ReadOptions) ?? [];
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load users from {Path}", _usersPath);
            return [];
        }
    }

    private void SaveUsers(List<UserAccount> users)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_usersPath)!);
        string json = JsonSerializer.Serialize(users, WriteOptions);
        string tempPath = _usersPath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, _usersPath, true);
    }

    private static string HashPassword(string password, string salt)
    {
        byte[] saltBytes = Convert.FromBase64String(salt);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            saltBytes,
            100_000,
            HashAlgorithmName.SHA256,
            32
        );
        return Convert.ToBase64String(hash);
    }

    private static string GenerateSalt()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        return Convert.ToBase64String(salt);
    }

    private static string GeneratePassword()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(48);
        string raw = Convert
            .ToBase64String(bytes)
            .Replace("+", "")
            .Replace("/", "")
            .Replace("=", "");
        return raw.Substring(0, Math.Min(32, raw.Length));
    }
}
