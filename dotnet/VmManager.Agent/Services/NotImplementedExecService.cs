using VmManager.Contracts.Interfaces;

namespace VmManager.Agent.Services;

/// <summary>
/// Stub exec service for backends that do not yet support in-VM execution.
/// Throws NotSupportedException to produce a clear 502 response.
/// </summary>
public sealed class NotImplementedExecService : IVmExecService
{
    public Task<VmExecResult> ExecAsync(
        string vmName, string script, string vmUsername, string vmPassword,
        int timeoutSeconds, CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException(
            "In-VM exec is not supported by this backend. " +
            "Requires Hyper-V (WinRM + PowerShell Direct)."
        );
    }
}
