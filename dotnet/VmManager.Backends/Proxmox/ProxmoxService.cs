using Microsoft.Extensions.Logging;
using VmManager.Contracts.Interfaces;
using VmManager.Contracts.Models;

namespace VmManager.Backends.Proxmox;

public class ProxmoxService : IVmBackend
{
    private readonly ILogger<ProxmoxService> _logger;
    private readonly IVmTrackingService _tracking;

    public ProxmoxVmService Vms { get; }
    public ProxmoxSnapshotService Snapshots { get; }
    public ProxmoxImportService Import { get; }

    public ProxmoxService(
        ILogger<ProxmoxService> logger,
        ProxmoxVmService vms,
        ProxmoxSnapshotService snapshots,
        ProxmoxImportService import,
        IVmTrackingService tracking
    )
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(vms);
        ArgumentNullException.ThrowIfNull(snapshots);
        ArgumentNullException.ThrowIfNull(import);
        ArgumentNullException.ThrowIfNull(tracking);
        _logger = logger;
        Vms = vms;
        Snapshots = snapshots;
        Import = import;
        _tracking = tracking;
    }

    public async Task<List<VmInstance>> GetVmsAsync()
    {
        List<VmInstance> allPoolVms = await Vms.GetVmsAsync();
        Dictionary<string, VmOrigin?> tracked = _tracking.LoadAll();
        return allPoolVms.Where(vm => tracked.ContainsKey(vm.Name)).ToList();
    }

    public Task StartVmAsync(string name) => Vms.StartVmAsync(name);

    public Task StopVmAsync(string name) => Vms.StopVmAsync(name);

    public Task DeleteVmAsync(string name) => Vms.DeleteVmAsync(name);

    public Task RenameVmAsync(string currentName, string newName) =>
        Vms.RenameVmAsync(currentName, newName);

    public Task<bool> ResetVmAsync(string name) => Vms.ResetVmAsync(name, Snapshots);

    public Task ConnectToVmAsync(string vmName, string username = "", string password = "") =>
        Vms.ConnectToVmAsync(vmName, username, password);

    public Task<List<VmSnapshot>> GetSnapshotsAsync(string vmName) =>
        Snapshots.GetSnapshotsAsync(vmName);

    public Task CreateSnapshotAsync(string vmName, string snapshotName) =>
        Snapshots.CreateSnapshotAsync(vmName, snapshotName);

    public Task RestoreSnapshotAsync(string vmName, string snapshotId) =>
        Snapshots.RestoreSnapshotAsync(vmName, snapshotId);

    public Task DeleteSnapshotAsync(string vmName, string snapshotId) =>
        Snapshots.DeleteSnapshotAsync(vmName, snapshotId);

    public Task ExportSnapshotAsync(string snapshotId, string destDir) =>
        Snapshots.ExportSnapshotAsync(snapshotId, destDir);

    public Task ImportVmAsync(
        string extractedFolder,
        string localVmPath,
        int memoryMb,
        int cpuCount,
        string? vmName = null,
        bool skipDefaultNetwork = false,
        Action<string>? onStatus = null,
        CancellationToken cancellationToken = default,
        string? vmSwitch = null
    ) =>
        Import.ImportVmAsync(
            extractedFolder,
            localVmPath,
            memoryMb,
            cpuCount,
            vmName,
            skipDefaultNetwork,
            onStatus,
            cancellationToken
        );

    public Task ConfigureLocaleAsync(
        string vmName,
        string username,
        string password,
        string locale = "de-DE",
        string keyboardLayout = "00000407",
        string timezone = "",
        Action<string>? onStatus = null
    ) =>
        Import.ConfigureLocaleAsync(
            vmName,
            username,
            password,
            locale,
            keyboardLayout,
            timezone,
            onStatus
        );

    public Task RunPostCreationAsync(
        string vmName,
        string username,
        string password,
        bool renameComputer,
        string? postCreationScript = null,
        Action<string>? onStatus = null
    ) =>
        Import.RunPostCreationAsync(
            vmName,
            username,
            password,
            renameComputer,
            postCreationScript,
            onStatus
        );

    public Task ConfigureAndFinalizeAsync(
        string vmName,
        string username,
        string password,
        string? locale,
        string? keyboardLayout,
        string? timezone,
        bool renameComputer,
        string? postCreationScript,
        Action<string>? onStatus = null
    ) =>
        Import.ConfigureAndFinalizeAsync(
            vmName,
            username,
            password,
            locale,
            keyboardLayout,
            timezone,
            renameComputer,
            postCreationScript,
            onStatus
        );

    public async Task CloneVmFromSnapshotAsync(string vmName, string snapshotName, string newVmName)
    {
        _logger.LogInformation(
            "Cloning VM {VmName} snapshot {Snap} to {NewVm}",
            vmName,
            snapshotName,
            newVmName
        );
        string tempDir = Path.Combine(Path.GetTempPath(), $"vmm-clone-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);
            string compositeId = vmName + ":" + snapshotName;
            await Snapshots.ExportSnapshotAsync(compositeId, tempDir);
            await Import.ImportVmAsync(tempDir, "/var/lib/vmmanager", 4096, 2, newVmName);
        }
        finally
        {
            try
            {
                Directory.Delete(tempDir, true);
            }
            catch { }
        }
    }

    public async Task ResetDiskAsync(string name)
    {
        _logger.LogInformation("Resetting VM {VmName} to base snapshot", name);
        bool reset = await Vms.ResetVmAsync(name, Snapshots);
        if (!reset)
            throw new InvalidOperationException($"VM '{name}' has no snapshots to reset to.");
    }

    public Task<string?> TroubleshootAsync() => Task.FromResult<string?>(null);
}
