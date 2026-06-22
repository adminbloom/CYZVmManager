namespace VmManager.Contracts.Interfaces;

/// <summary>
/// Executes scripts inside a VM. Implementations are backend-specific
/// (e.g. WinRM + PowerShell Direct for Hyper-V, guest agent for Proxmox).
/// </summary>
public interface IVmExecService
{
    /// <summary>
    /// Execute a PowerShell script inside the named VM.
    /// </summary>
    /// <param name="vmName">VM name</param>
    /// <param name="script">Script to execute</param>
    /// <param name="vmUsername">VM login username</param>
    /// <param name="vmPassword">VM login password</param>
    /// <param name="timeoutSeconds">Maximum execution time</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Exit code, stdout, and stderr from the script.</returns>
    Task<VmExecResult> ExecAsync(
        string vmName,
        string script,
        string vmUsername,
        string vmPassword,
        int timeoutSeconds,
        CancellationToken cancellationToken = default
    );
}

/// <summary>Result of executing a script inside a VM.</summary>
public record VmExecResult(int ExitCode, string StdOut, string StdErr);
