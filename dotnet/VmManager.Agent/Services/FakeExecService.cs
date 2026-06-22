using VmManager.Contracts.Interfaces;

namespace VmManager.Agent.Services;

/// <summary>
/// Fake exec service for development/testing. Returns a canned response.
/// </summary>
public sealed class FakeExecService : IVmExecService
{
    private readonly ILogger<FakeExecService> _logger;

    public FakeExecService(ILogger<FakeExecService> logger)
    {
        _logger = logger;
    }

    public Task<VmExecResult> ExecAsync(
        string vmName, string script, string vmUsername, string vmPassword,
        int timeoutSeconds, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Fake exec in VM {VmName}: {Script}", vmName, script[..Math.Min(80, script.Length)]);
        return Task.FromResult(new VmExecResult(0, "fake output", ""));
    }
}
