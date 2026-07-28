using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using VmManager.Contracts.Models;

namespace VmManager.Agent.Services;

/// <summary>
/// Validates OIDC JWT tokens issued by Keycloak.
/// Fetches JWKS from the issuer's discovery endpoint and verifies
/// signature, issuer, audience, and expiry.
/// </summary>
public sealed class OidcTokenValidator : IDisposable
{
    private readonly HttpClient _http;
    private readonly ILogger<OidcTokenValidator>? _logger;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly string _clientId;
    private readonly string _clientSecret;

    private OidcDiscoveryDoc? _discovery;
    private JsonWebKeySet? _jwks;
    private DateTime _discoveryFetchedAt = DateTime.MinValue;
    private DateTime _jwksFetchedAt = DateTime.MinValue;

    private static readonly TimeSpan DiscoveryTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan JwksTtl = TimeSpan.FromMinutes(15);

    public OidcTokenValidator(
        string issuer,
        string audience,
        string clientId = "",
        string clientSecret = "",
        ILogger<OidcTokenValidator>? logger = null)
    {
        _issuer = issuer.TrimEnd('/');
        _audience = audience;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _logger = logger;

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    /// <summary>
    /// Validate a Bearer token and return the authenticated user.
    /// </summary>
    public AuthenticatedUser? ValidateBearerToken(string authHeader)
    {
        if (string.IsNullOrWhiteSpace(authHeader))
            return null;

        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        var token = authHeader.Substring("Bearer ".Length).Trim();
        return ValidateToken(token);
    }

    /// <summary>
    /// Validate a JWT token string and return the authenticated user.
    /// </summary>
    public AuthenticatedUser? ValidateToken(string token)
    {
        try
        {
            var discovery = GetDiscoveryDoc();
            var jwks = GetJwks(discovery);

            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = !string.IsNullOrEmpty(_audience),
                ValidAudience = _audience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = jwks.GetSigningKeys(),
                ClockSkew = TimeSpan.FromSeconds(60),
            };

            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(token, validationParams, out var securityToken);

            return PrincipalToUser(principal, securityToken as JwtSecurityToken);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning("JWT validation failed: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Get a client credentials token for service-to-service calls.
    /// </summary>
    public async Task<string?> GetClientCredentialsTokenAsync(string scope = "")
    {
        var discovery = GetDiscoveryDoc();
        var tokenEndpoint = discovery.TokenEndpoint;

        var formData = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret,
        };
        if (!string.IsNullOrEmpty(scope))
            formData["scope"] = scope;

        var content = new FormUrlEncodedContent(formData);
        var resp = await _http.PostAsync(tokenEndpoint, content);
        resp.EnsureSuccessStatusCode();

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("access_token").GetString();
    }

    private AuthenticatedUser PrincipalToUser(ClaimsPrincipal principal, JwtSecurityToken? jwt)
    {
        var user = new AuthenticatedUser();
        var claims = principal.Claims.ToList();

        user.Username = claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                        ?? claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value
                        ?? claims.FirstOrDefault(c => c.Type == "sub")?.Value
                        ?? jwt?.Subject
                        ?? "";
        user.Email = claims.FirstOrDefault(c => c.Type == "email")?.Value
                     ?? claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                     ?? "";

        // Keycloak realm roles (roles-and-scopes.md): platform_admin / data_admin / user
        var roles = ExtractRealmRoles(claims, jwt);
        // Agent admin = platform or data admin (Hyper-V ops need elevated access)
        user.IsAdmin = roles.Contains("platform_admin") || roles.Contains("data_admin");

        var scopeClaim = claims.FirstOrDefault(c => c.Type == "scope")
                         ?? claims.FirstOrDefault(c => c.Type == "scp");
        if (scopeClaim != null)
        {
            user.Permissions = new HashSet<string>(
                scopeClaim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            );
        }
        else if (jwt?.Payload.TryGetValue("scope", out var scopeObj) == true && scopeObj is string scopeStr)
        {
            user.Permissions = new HashSet<string>(
                scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            );
        }

        return user;
    }

    private static List<string> ExtractRealmRoles(List<Claim> claims, JwtSecurityToken? jwt)
    {
        var fromClaim = ExtractRealmRolesFromJson(
            claims.FirstOrDefault(c => c.Type == "realm_access")?.Value
        );
        if (fromClaim.Count > 0)
            return fromClaim;

        if (jwt?.Payload.TryGetValue("realm_access", out var ra) == true)
        {
            string json = ra switch
            {
                string s => s,
                JsonElement je => je.GetRawText(),
                _ => ra?.ToString() ?? "",
            };
            return ExtractRealmRolesFromJson(json);
        }

        return [];
    }

    private static List<string> ExtractRealmRolesFromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("roles", out var rolesEl))
            {
                return rolesEl.EnumerateArray()
                    .Select(r => r.GetString() ?? "")
                    .Where(r => r.Length > 0)
                    .ToList();
            }
        }
        catch
        {
            // ignore malformed realm_access
        }

        return [];
    }

    private OidcDiscoveryDoc GetDiscoveryDoc()
    {
        if (_discovery != null && DateTime.UtcNow - _discoveryFetchedAt < DiscoveryTtl)
            return _discovery;

        var url = $"{_issuer}/.well-known/openid-configuration";
        var resp = _http.GetStringAsync(url).GetAwaiter().GetResult();
        using var doc = JsonDocument.Parse(resp);
        var root = doc.RootElement;

        _discovery = new OidcDiscoveryDoc
        {
            Issuer = root.GetProperty("issuer").GetString() ?? "",
            AuthorizationEndpoint = root.GetProperty("authorization_endpoint").GetString() ?? "",
            TokenEndpoint = root.GetProperty("token_endpoint").GetString() ?? "",
            JwksUri = root.GetProperty("jwks_uri").GetString() ?? "",
            EndSessionEndpoint = root.TryGetProperty("end_session_endpoint", out var ese)
                ? ese.GetString() ?? "" : "",
        };
        _discoveryFetchedAt = DateTime.UtcNow;
        _logger?.LogDebug("OIDC discovery fetched from {Url}", url);
        return _discovery;
    }

    private JsonWebKeySet GetJwks(OidcDiscoveryDoc discovery)
    {
        if (_jwks != null && DateTime.UtcNow - _jwksFetchedAt < JwksTtl)
            return _jwks;

        var json = _http.GetStringAsync(discovery.JwksUri).GetAwaiter().GetResult();
        _jwks = new JsonWebKeySet(json);
        _jwksFetchedAt = DateTime.UtcNow;
        _logger?.LogDebug("JWKS fetched from {Uri}", discovery.JwksUri);
        return _jwks;
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}

internal sealed class OidcDiscoveryDoc
{
    public string Issuer { get; set; } = "";
    public string AuthorizationEndpoint { get; set; } = "";
    public string TokenEndpoint { get; set; } = "";
    public string JwksUri { get; set; } = "";
    public string EndSessionEndpoint { get; set; } = "";
}
