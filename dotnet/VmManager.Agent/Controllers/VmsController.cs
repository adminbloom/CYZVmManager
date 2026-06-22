using System.Net.Sockets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VmManager.Agent.Services;
using VmManager.Agent.Services.Monitoring;
using VmManager.Backends.Shared;
using VmManager.Contracts.Interfaces;
using VmManager.Contracts.Models;

namespace VmManager.Agent.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class VmsController : ControllerBase
{
    private readonly IVmBackend _backend;
    private readonly INetworkService _networkService;
    private readonly IVmTrackingService _vmTrackingService;
    private readonly NetworkTrackingService _networkTrackingService;
    private readonly SettingsService _settingsService;
    private readonly IBackgroundTaskManager _backgroundTaskManager;
    private readonly IPreflightService _preflightService;
    private readonly IVmIpResolver _ipResolver;
    private readonly AuthorizationService _authorizationService;
    private readonly VmOwnershipService _ownershipService;
    private readonly VmSharingService _sharingService;
    private readonly EmailService _emailService;
    private readonly UserService _userService;
    private readonly VmStopTracker _vmStopTracker;
    private readonly IVmExecService _execService;
    private readonly ILogger<VmsController> _logger;

    public VmsController(
        IVmBackend backend,
        INetworkService networkService,
        IVmTrackingService vmTrackingService,
        NetworkTrackingService networkTrackingService,
        SettingsService settingsService,
        IBackgroundTaskManager backgroundTaskManager,
        IPreflightService preflightService,
        IVmIpResolver ipResolver,
        AuthorizationService authorizationService,
        VmOwnershipService ownershipService,
        VmSharingService sharingService,
        EmailService emailService,
        UserService userService,
        VmStopTracker vmStopTracker,
        IVmExecService execService,
        ILogger<VmsController> logger
    )
    {
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(networkService);
        ArgumentNullException.ThrowIfNull(vmTrackingService);
        ArgumentNullException.ThrowIfNull(networkTrackingService);
        ArgumentNullException.ThrowIfNull(settingsService);
        ArgumentNullException.ThrowIfNull(backgroundTaskManager);
        ArgumentNullException.ThrowIfNull(preflightService);
        ArgumentNullException.ThrowIfNull(ipResolver);
        ArgumentNullException.ThrowIfNull(authorizationService);
        ArgumentNullException.ThrowIfNull(ownershipService);
        ArgumentNullException.ThrowIfNull(execService);
        ArgumentNullException.ThrowIfNull(sharingService);
        ArgumentNullException.ThrowIfNull(emailService);
        ArgumentNullException.ThrowIfNull(userService);
        ArgumentNullException.ThrowIfNull(vmStopTracker);
        ArgumentNullException.ThrowIfNull(logger);
        _backend = backend;
        _networkService = networkService;
        _vmTrackingService = vmTrackingService;
        _networkTrackingService = networkTrackingService;
        _settingsService = settingsService;
        _backgroundTaskManager = backgroundTaskManager;
        _preflightService = preflightService;
        _ipResolver = ipResolver;
        _authorizationService = authorizationService;
        _ownershipService = ownershipService;
        _sharingService = sharingService;
        _emailService = emailService;
        _userService = userService;
        _vmStopTracker = vmStopTracker;
        _execService = execService;
        _logger = logger;
    }

    [HttpGet]
    [ProducesResponseType(typeof(List<VmInstance>), 200)]
    public async Task<IActionResult> ListVms()
    {
        List<VmInstance> allVms = [];

        try
        {
            List<VmInstance> vms = await _backend.GetVmsAsync();
            allVms.AddRange(vms);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load VMs");
        }

        Dictionary<string, VmOrigin?> managedVms = _vmTrackingService.LoadAll();
        Dictionary<string, string> notes = _vmTrackingService.LoadNotes();

        foreach (VmInstance vm in allVms)
        {
            if (notes.TryGetValue(vm.Name, out string? note))
                vm.Notes = note;
            vm.IsManaged = managedVms.ContainsKey(vm.Name);
            if (managedVms.TryGetValue(vm.Name, out VmOrigin? vmOrigin))
                vm.Origin = vmOrigin;

            vm.Owner = _ownershipService.GetOwner(vm.Name);
            List<VmShareEntry> shares = _sharingService.GetSharesForVm(vm.Name);
            vm.SharedWith = shares.Select(s => s.SharedWithUsername).ToList();

            string currentUsername = User.Identity?.Name ?? "";
            if (
                User.IsInRole("Admin")
                || string.Equals(vm.Owner, currentUsername, StringComparison.OrdinalIgnoreCase)
            )
            {
                vm.EffectivePermissions = Permission.All;
            }
            else
            {
                VmShareEntry? myShare = shares.FirstOrDefault(s =>
                    string.Equals(
                        s.SharedWithUsername,
                        currentUsername,
                        StringComparison.OrdinalIgnoreCase
                    )
                );
                if (myShare != null)
                    vm.EffectivePermissions = myShare.GrantedPermissions;
            }
        }

        List<VmInstance> filtered = allVms
            .Where(vm => _authorizationService.CanViewVm(User, vm.Name))
            .ToList();

        return Ok(filtered);
    }

    [HttpPost("{name}/start")]
    [ProducesResponseType(204)]
    [ProducesResponseType(typeof(object), 400)]
    [ProducesResponseType(typeof(object), 500)]
    public async Task<IActionResult> StartVm(string name)
    {
        if (!_authorizationService.CanAccessVm(User, name, Permission.VmStart))
            return Forbid();

        _logger.LogInformation("Starting VM {VmName}", name);

        try
        {
            string? ramError = await _preflightService.CheckRamForVmAsync(name);
            if (ramError != null)
            {
                _logger.LogWarning("RAM preflight failed for {VmName}: {Error}", name, ramError);
                return BadRequest(new { error = ramError });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "RAM preflight check threw for {VmName}, proceeding anyway",
                name
            );
        }

        try
        {
            await _backend.StartVmAsync(name);
            RunPostStartupScriptInBackground(name);
            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start VM {VmName}", name);
            return StatusCode(500, new { error = "Failed to start VM: " + ex.Message });
        }
    }

    [HttpPost("{name}/stop")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> StopVm(string name)
    {
        if (!_authorizationService.CanAccessVm(User, name, Permission.VmStop))
            return Forbid();

        _logger.LogInformation("Stopping VM {VmName}", name);
        _vmStopTracker.RecordStop(name);
        await _backend.StopVmAsync(name);
        return NoContent();
    }

    [HttpGet("{name}/rdp-ready")]
    [ProducesResponseType(typeof(object), 200)]
    public async Task<IActionResult> IsRdpReady(string name)
    {
        string? ip = await _ipResolver.ResolveIpAsync(name);
        if (ip == null)
            return Ok(new { ready = false });

        try
        {
            using TcpClient tcp = new TcpClient();
            Task connectTask = tcp.ConnectAsync(ip, 3389);
            bool connected =
                await Task.WhenAny(connectTask, Task.Delay(2000)) == connectTask && tcp.Connected;
            return Ok(new { ready = connected });
        }
        catch
        {
            return Ok(new { ready = false });
        }
    }

    /// <summary>
    /// Execute a PowerShell script inside a VM. Tries WinRM first (network),
    /// falls back to PowerShell Direct (VM bus) when WinRM is unavailable.
    /// Requires AllowExec=true in settings.json and the vm.exec permission.
    /// </summary>
    /// <param name="name">VM name</param>
    /// <param name="request">Script and timeout</param>
    /// <returns>Exit code, stdout, and stderr from the script execution.</returns>
    /// <response code="200">Script executed (check exitCode for result)</response>
    /// <response code="400">Script is empty or too large</response>
    /// <response code="403">Exec is disabled or user lacks permission</response>
    /// <response code="502">Execution failed</response>
    /// <response code="503">VM credentials not configured</response>
    /// <response code="504">Script execution timed out</response>
    [HttpPost("{name}/exec")]
    [Authorize(Policy = Permission.VmExec)]
    [ProducesResponseType(typeof(object), 200)]
    [ProducesResponseType(typeof(object), 400)]
    [ProducesResponseType(typeof(object), 403)]
    [ProducesResponseType(typeof(object), 502)]
    [ProducesResponseType(typeof(object), 503)]
    [ProducesResponseType(typeof(object), 504)]
    public async Task<IActionResult> ExecInVm(string name, [FromBody] ExecVmRequest request)
    {
        AppSettings settings = _settingsService.Load();
        if (!settings.AllowExec)
            return StatusCode(403, new { error = "Exec is disabled on this agent. Set AllowExec=true in settings.json to enable." });

        if (!_authorizationService.CanAccessVm(User, name, Permission.VmExec))
            return Forbid();

        if (string.IsNullOrWhiteSpace(request.Script))
            return BadRequest(new { error = "Script is required." });

        if (request.Script.Length > 1_000_000)
            return BadRequest(new { error = "Script too large (max 1 MB)." });

        if (string.IsNullOrWhiteSpace(settings.DefaultVmUsername)
            || string.IsNullOrWhiteSpace(settings.DefaultVmPassword))
            return StatusCode(503, new { error = "DefaultVmUsername/DefaultVmPassword not configured in settings.json." });

        int timeoutSeconds = request.Timeout > 0 ? request.Timeout : 60;
        string scriptPreview = request.Script.Length > 200
            ? request.Script[..200] + "..."
            : request.Script;
        string user = User.Identity?.Name ?? "?";

        _logger.LogInformation(
            "Exec in VM {VmName} by user {User}, timeout={Timeout}s, scriptLen={Len}, script={Preview}",
            name, user, timeoutSeconds, request.Script.Length, scriptPreview
        );

        try
        {
            VmExecResult result = await _execService.ExecAsync(
                name, request.Script, settings.DefaultVmUsername!,
                settings.DefaultVmPassword!, timeoutSeconds
            );
            return Ok(new { exitCode = result.ExitCode, stdout = result.StdOut, stderr = result.StdErr });
        }
        catch (TimeoutException)
        {
            return StatusCode(504, new { error = $"Exec timed out after {timeoutSeconds}s." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exec failed in VM {VmName}", name);
            return StatusCode(502, new { error = "VM execution failed: " + ex.Message });
        }
    }

    [HttpDelete("{name}")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> DeleteVm(string name)
    {
        if (
            !_authorizationService.IsOwnerOrAdmin(User, name)
            || !_authorizationService.HasPermission(User, Permission.VmDelete)
        )
            return Forbid();

        _logger.LogInformation("Deleting VM {VmName}", name);
        string vmOwner = _ownershipService.GetOwner(name);
        string currentUser = User.Identity?.Name ?? "admin";

        _vmStopTracker.RecordStop(name);
        await _backend.DeleteVmAsync(name);
        _vmTrackingService.UntrackVm(name);
        _vmTrackingService.RemoveNote(name);
        _ownershipService.RemoveOwner(name);
        _sharingService.RemoveAllSharesForVm(name);

        if (!string.Equals(vmOwner, currentUser, StringComparison.OrdinalIgnoreCase))
            _ = SendVmDeletedEmailAsync(vmOwner, name, currentUser);

        AppSettings settings = _settingsService.Load();
        List<string> emptyNetworks = _networkTrackingService.DecrementReferences(name);
        if (settings.AutoCleanupUnusedNetworks)
        {
            foreach (string networkId in emptyNetworks)
            {
                string switchName = "VmMgr-" + networkId;
                try
                {
                    await _networkService.RemoveSwitchAsync(switchName);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to cleanup switch {Switch}", switchName);
                }
                _networkTrackingService.Remove(networkId);
            }
        }

        return NoContent();
    }

    [HttpPut("{name}/rename")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> RenameVm(string name, [FromBody] RenameRequest request)
    {
        if (
            !_authorizationService.IsOwnerOrAdmin(User, name)
            || !_authorizationService.HasPermission(User, Permission.VmRename)
        )
            return Forbid();

        string? nameError = VmNameValidator.GetError(request.NewName);
        if (nameError != null)
            return BadRequest(new { error = nameError });

        _logger.LogInformation("Renaming VM {VmName} to {NewName}", name, request.NewName);
        await _backend.RenameVmAsync(name, request.NewName);

        VmOrigin? origin = _vmTrackingService.GetOrigin(name);
        if (origin != null)
        {
            _vmTrackingService.UntrackVm(name);
            _vmTrackingService.TrackVm(request.NewName, origin);
        }

        string? existingNote = _vmTrackingService.LoadNotes().GetValueOrDefault(name);
        if (existingNote != null)
        {
            _vmTrackingService.RemoveNote(name);
            _vmTrackingService.SaveNote(request.NewName, existingNote);
        }

        _ownershipService.RenameVm(name, request.NewName);
        _sharingService.RenameVm(name, request.NewName);

        return NoContent();
    }

    [HttpPost("{name}/reset")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> ResetVm(string name)
    {
        if (!_authorizationService.CanAccessVm(User, name, Permission.VmReset))
            return Forbid();

        _logger.LogInformation("Resetting VM {VmName} to base", name);
        bool restored = await _backend.ResetVmAsync(name);
        if (!restored)
            await _backend.ResetDiskAsync(name);
        return NoContent();
    }

    [HttpPut("{name}/notes")]
    [ProducesResponseType(204)]
    public IActionResult SaveNotes(string name, [FromBody] NotesRequest request)
    {
        if (!_authorizationService.CanAccessVm(User, name, Permission.VmViewOwn))
            return Forbid();

        if (string.IsNullOrWhiteSpace(request.Notes))
            _vmTrackingService.RemoveNote(name);
        else
            _vmTrackingService.SaveNote(name, request.Notes);
        return NoContent();
    }

    [HttpPost("{name}/apply-locale")]
    [ProducesResponseType(typeof(object), 202)]
    public IActionResult ApplyLocale(string name)
    {
        if (
            !_authorizationService.IsOwnerOrAdmin(User, name)
            || !_authorizationService.HasPermission(User, Permission.VmApplyLocale)
        )
            return Forbid();

        _logger.LogInformation("Applying locale to VM {VmName}", name);

        AppSettings settings = _settingsService.Load();
        if (
            string.IsNullOrWhiteSpace(settings.DefaultLocale)
            && string.IsNullOrWhiteSpace(settings.DefaultTimezone)
        )
            return BadRequest(new { error = "No locale or timezone configured" });

        if (
            string.IsNullOrWhiteSpace(settings.DefaultVmUsername)
            || string.IsNullOrWhiteSpace(settings.DefaultVmPassword)
        )
            return BadRequest(
                new { error = "VM username and password must be configured in settings" }
            );

        IBackgroundTask task = _backgroundTaskManager.StartTask(
            "Applying locale to " + name,
            async ctx =>
            {
                ctx.ReportProgress(-1, "Booting VM and connecting...");
                await _backend.ConfigureLocaleAsync(
                    name,
                    settings.DefaultVmUsername,
                    settings.DefaultVmPassword,
                    settings.DefaultLocale,
                    settings.DefaultKeyboardLayout,
                    settings.DefaultTimezone
                );
                ctx.Log("Locale applied successfully");
            },
            isCancellable: false
        );

        return Accepted(new { taskId = task.Id, title = task.Title });
    }

    [HttpGet("{name}/sessions")]
    [ProducesResponseType(typeof(RdpShadowSessionsResponse), 200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(503)]
    public async Task<IActionResult> GetSessions(string name)
    {
        if (!User.IsInRole("Admin"))
            return Forbid();

        string? ip = await _ipResolver.ResolveIpAsync(name);
        if (ip == null)
            return StatusCode(503, new { error = "VM IP not available. Is the VM running?" });

        AppSettings settings = _settingsService.Load();
        if (
            string.IsNullOrWhiteSpace(settings.DefaultVmUsername)
            || string.IsNullOrWhiteSpace(settings.DefaultVmPassword)
        )
            return BadRequest(new { error = "VM credentials not configured in settings" });

        try
        {
            using Backends.Shared.WinRmClient client = new Backends.Shared.WinRmClient(
                ip,
                settings.DefaultVmUsername,
                settings.DefaultVmPassword
            );
            Backends.Shared.WinRmResult result = await client.RunPowerShellAsync("query session");
            List<RdpShadowSession> sessions = ParseQuerySessionOutput(result.StdOut);

            return Ok(new RdpShadowSessionsResponse { VmIp = ip, Sessions = sessions });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to query sessions on VM {VmName}", name);
            return StatusCode(503, new { error = "Failed to query sessions: " + ex.Message });
        }
    }

    private static List<RdpShadowSession> ParseQuerySessionOutput(string output)
    {
        List<RdpShadowSession> sessions = [];
        string[] lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 2)
            return sessions;

        string header = lines[0];
        int usernameCol = header.IndexOf("USERNAME", StringComparison.OrdinalIgnoreCase);
        int idCol = header.IndexOf(" ID", StringComparison.OrdinalIgnoreCase);
        int stateCol = header.IndexOf("STATE", StringComparison.OrdinalIgnoreCase);

        if (usernameCol < 0 || idCol < 0 || stateCol < 0)
            return sessions;

        idCol++;

        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i].TrimEnd('\r');
            if (line.Length < stateCol + 1)
                continue;

            string cleanLine = line.StartsWith('>') ? " " + line[1..] : line;

            string sessionName =
                usernameCol <= cleanLine.Length ? cleanLine[..usernameCol].Trim() : "";
            string username = idCol <= cleanLine.Length ? cleanLine[usernameCol..idCol].Trim() : "";
            string idStr = stateCol <= cleanLine.Length ? cleanLine[idCol..stateCol].Trim() : "";
            string state = stateCol <= cleanLine.Length ? cleanLine[stateCol..].Trim() : "";

            int spaceIdx = state.IndexOf(' ');
            if (spaceIdx > 0)
                state = state[..spaceIdx];

            if (!int.TryParse(idStr, out int sessionId))
                continue;
            if (!string.Equals(state, "Active", StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.IsNullOrEmpty(username))
                continue;

            sessions.Add(
                new RdpShadowSession
                {
                    SessionName = sessionName,
                    Username = username,
                    SessionId = sessionId,
                    State = state,
                }
            );
        }

        return sessions;
    }

    private void RunPostStartupScriptInBackground(string vmName)
    {
        AppSettings settings = _settingsService.Load();
        if (string.IsNullOrWhiteSpace(settings.PostStartupScript))
            return;
        if (
            string.IsNullOrWhiteSpace(settings.DefaultVmUsername)
            || string.IsNullOrWhiteSpace(settings.DefaultVmPassword)
        )
            return;

        string script = settings.PostStartupScript;
        string username = settings.DefaultVmUsername;
        string password = settings.DefaultVmPassword;

        _ = Task.Run(async () =>
        {
            try
            {
                string? ip = null;
                for (int i = 0; i < 60; i++)
                {
                    ip = await _ipResolver.ResolveIpAsync(vmName);
                    if (ip != null)
                        break;
                    await Task.Delay(5000);
                }
                if (ip == null)
                {
                    _logger.LogWarning(
                        "Post-startup script skipped for {VmName}: no IP found",
                        vmName
                    );
                    return;
                }

                bool winrmReady = false;
                for (int j = 0; j < 60; j++)
                {
                    try
                    {
                        using TcpClient tcp = new TcpClient();
                        await tcp.ConnectAsync(ip, 5985).WaitAsync(TimeSpan.FromSeconds(2));
                        winrmReady = true;
                        break;
                    }
                    catch
                    {
                        await Task.Delay(3000);
                    }
                }
                if (!winrmReady)
                {
                    _logger.LogWarning(
                        "Post-startup script skipped for {VmName}: WinRM not available",
                        vmName
                    );
                    return;
                }

                _logger.LogInformation(
                    "Running post-startup script on {VmName} ({Ip})",
                    vmName,
                    ip
                );
                await Backends.Shared.WinRmLocaleHelper.RunWinRmPowerShellAsync(
                    ip,
                    username,
                    password,
                    script
                );
                _logger.LogInformation("Post-startup script completed for {VmName}", vmName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Post-startup script failed for {VmName}", vmName);
            }
        });
    }

    private async Task SendVmDeletedEmailAsync(
        string ownerUsername,
        string vmName,
        string deletedBy
    )
    {
        try
        {
            string? email = GetUserEmail(ownerUsername);
            if (string.IsNullOrWhiteSpace(email))
                return;

            string body =
                $@"
<h2>VM Deleted</h2>
<p>Your VM <b>{vmName}</b> has been deleted by <b>{deletedBy}</b>.</p>";

            await _emailService.SendAsync(email, "VM Deleted: " + vmName, body);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send VM deleted email for {VmName}", vmName);
        }
    }

    private string? GetUserEmail(string username)
    {
        UserAccount? user = _userService.GetByUsername(username);
        if (user == null)
            return null;
        if (user.IsAdmin)
            return string.IsNullOrWhiteSpace(user.Email) ? null : user.Email;
        return EmailValidator.IsValid(user.Username) ? user.Username : null;
    }
}
