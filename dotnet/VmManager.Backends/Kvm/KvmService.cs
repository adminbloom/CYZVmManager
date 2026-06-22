using Microsoft.Extensions.Logging;
using VmManager.Contracts.Interfaces;
using VmManager.Contracts.Models;

namespace VmManager.Backends.Kvm;

public class KvmService : IVmBackend
{
    private readonly ILogger<KvmService> _logger;

    public KvmVmService Vms { get; }
    public KvmSnapshotService Snapshots { get; }
    public KvmImportService Import { get; }

    public KvmService(
        ILogger<KvmService> logger,
        KvmVmService vms,
        KvmSnapshotService snapshots,
        KvmImportService import
    )
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(vms);
        ArgumentNullException.ThrowIfNull(snapshots);
        ArgumentNullException.ThrowIfNull(import);
        _logger = logger;
        Vms = vms;
        Snapshots = snapshots;
        Import = import;
    }

    public Task<List<VmInstance>> GetVmsAsync() => Vms.GetVmsAsync();

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

    public Task ExportSnapshotAsync(string snapshotId, string destDir) =>
        Snapshots.ExportSnapshotAsync(snapshotId, destDir);

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

    public async Task RunPostCreationAsync(
        string vmName,
        string username,
        string password,
        bool renameComputer,
        string? postCreationScript = null,
        Action<string>? onStatus = null
    )
    {
        if (!renameComputer && string.IsNullOrWhiteSpace(postCreationScript))
            return;

        onStatus?.Invoke("Running post-creation tasks...");
        await Import.RunPostCreationViaWinRmAsync(
            vmName,
            username,
            password,
            renameComputer,
            postCreationScript,
            onStatus
        );
    }

    public async Task CloneVmFromSnapshotAsync(string vmName, string snapshotName, string newVmName)
    {
        _logger.LogInformation(
            "Cloning VM {VmName} snapshot {SnapshotName} to {NewVmName}",
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

            string appPaths = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData
            );
            string localVmPath = Path.Combine(appPaths, "VmManager", "VMs");
            await Import.ImportVmAsync(tempDir, localVmPath, 4096, 2, newVmName);
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
