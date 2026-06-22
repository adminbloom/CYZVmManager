using System.Text.Json;
using Microsoft.Extensions.Logging;
using VmManager.Backends.Shared;
using VmManager.Contracts.Interfaces;

namespace VmManager.Backends.HyperV;

/// <summary>
/// Executes scripts inside Hyper-V VMs. Tries WinRM (network) first,
/// falls back to PowerShell Direct (VM bus) when WinRM is unavailable.
/// </summary>
public class HyperVExecService : IVmExecService
{
    private readonly IVmIpResolver _ipResolver;
    private readonly PowerShellRunner _ps;
    private readonly ILogger<HyperVExecService> _logger;

    public HyperVExecService(
        IVmIpResolver ipResolver,
        PowerShellRunner ps,
        ILogger<HyperVExecService> logger
    )
    {
        ArgumentNullException.ThrowIfNull(ipResolver);
        ArgumentNullException.ThrowIfNull(ps);
        ArgumentNullException.ThrowIfNull(logger);
        _ipResolver = ipResolver;
        _ps = ps;
        _logger = logger;
    }

    public async Task<VmExecResult> ExecAsync(
        string vmName,
        string script,
        string vmUsername,
        string vmPassword,
        int timeoutSeconds,
        CancellationToken cancellationToken = default
    )
    {
        string? ip = await _ipResolver.ResolveIpAsync(vmName, cancellationToken);

        if (ip != null)
        {
            _logger.LogInformation(
                "Exec in VM {VmName} ({Ip}) via WinRM, timeout={Timeout}s",
                vmName, ip, timeoutSeconds
            );

            try
            {
                using WinRmClient winRm = new(ip, vmUsername, vmPassword);
                Task<WinRmResult> execTask = winRm.RunPowerShellAsync(script);
                Task timeoutTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds), cancellationToken);

                if (await Task.WhenAny(execTask, timeoutTask) == timeoutTask)
                {
                    _logger.LogWarning("Exec in VM {VmName} timed out after {Timeout}s (WinRM)", vmName, timeoutSeconds);
                    throw new TimeoutException($"Exec timed out after {timeoutSeconds}s.");
                }

                WinRmResult result = await execTask;
                return new VmExecResult(result.ExitCode, result.StdOut, result.StdErr);
            }
            catch (TimeoutException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "WinRM exec failed in VM {VmName}, falling back to PowerShell Direct", vmName);
            }
        }

        return await ExecViaPowerShellDirect(vmName, script, vmUsername, vmPassword, timeoutSeconds, cancellationToken);
    }

    private async Task<VmExecResult> ExecViaPowerShellDirect(
        string vmName, string script, string vmUsername, string vmPassword,
        int timeoutSeconds, CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "Exec in VM {VmName} via PowerShell Direct, timeout={Timeout}s",
            vmName, timeoutSeconds
        );

        string scriptB64 = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
        string vmNameQ = PowerShellRunner.Q(vmName);
        string userQ = PowerShellRunner.Q(vmUsername);
        string passQ = PowerShellRunner.Q(vmPassword);

        string psScript = $$"""
            $cred = New-Object PSCredential({{userQ}}, (ConvertTo-SecureString {{passQ}} -AsPlainText -Force))
            $session = $null
            $tries = 0
            $maxTries = [Math]::Max(1, {{timeoutSeconds}} / 3)
            while ($tries -lt $maxTries -and -not $session) {
                try {
                    $session = New-PSSession -VMName {{vmNameQ}} -Credential $cred -ErrorAction Stop
                } catch {
                    Start-Sleep -Seconds 3
                    $tries++
                }
            }
            if (-not $session) { throw "VM did not become responsive via PowerShell Direct within $maxTries attempts." }
            try {
                $result = Invoke-Command -Session $session -ScriptBlock {
                    param($encoded)
                    $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
                    $sb = [ScriptBlock]::Create($decoded)
                    $stdout = & $sb 2>&1
                    $exitCode = $LASTEXITCODE
                    if ($null -eq $exitCode) { $exitCode = 0 }
                    [PSCustomObject]@{
                        exitCode = $exitCode
                        stdout   = ($stdout | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Out-String)
                        stderr   = ($stdout | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Out-String)
                    }
                } -ArgumentList '{{scriptB64}}'
            } finally {
                Remove-PSSession $session -ErrorAction SilentlyContinue
            }
            $result | ConvertTo-Json -Compress -Depth 3
            """;

        Task<string> psDirectTask = _ps.RunPsAsync(psScript);
        Task timeoutTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds + 30), cancellationToken);

        if (await Task.WhenAny(psDirectTask, timeoutTask) == timeoutTask)
        {
            _logger.LogWarning("Exec in VM {VmName} timed out after {Timeout}s (PowerShell Direct)", vmName, timeoutSeconds);
            throw new TimeoutException($"Exec timed out after {timeoutSeconds}s.");
        }

        string psOutput = (await psDirectTask).Trim();
        _logger.LogInformation("Exec in VM {VmName} via PowerShell Direct completed", vmName);

        int exitCode = 0;
        string stdout = psOutput;
        string stderr = "";

        try
        {
            using JsonDocument doc = JsonDocument.Parse(psOutput);
            JsonElement root = doc.RootElement;
            if (root.TryGetProperty("exitCode", out JsonElement ec))
                exitCode = ec.GetInt32();
            if (root.TryGetProperty("stdout", out JsonElement so))
                stdout = so.GetString() ?? "";
            if (root.TryGetProperty("stderr", out JsonElement se))
                stderr = se.GetString() ?? "";
        }
        catch (JsonException)
        {
            _logger.LogDebug("PowerShell Direct output was not JSON, returning raw output for VM {VmName}", vmName);
        }

        return new VmExecResult(exitCode, stdout.Trim(), stderr.Trim());
    }
}
