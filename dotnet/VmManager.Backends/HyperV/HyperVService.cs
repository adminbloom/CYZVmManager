using Microsoft.Extensions.Logging;
using VmManager.Contracts.Interfaces;
using VmManager.Contracts.Models;

namespace VmManager.Backends.HyperV;

/// <summary>
/// Thin facade that delegates to focused service classes while preserving
/// the original HyperVService API so callers don't break.
/// </summary>
public class HyperVService : IVmBackend
{
    private readonly ILogger<HyperVService> _logger;

    public HyperVVmService Vms { get; }
    public HyperVSnapshotService Snapshots { get; }
    public HyperVImportService Import { get; }

    public HyperVService(
        ILogger<HyperVService> logger,
        HyperVVmService vms,
        HyperVSnapshotService snapshots,
        HyperVImportService import
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
            vmSwitch
        );

    public async Task<string?> TroubleshootAsync() => await Vms.TroubleshootVmListingAsync();

    public Task<string> TroubleshootVmListingAsync() => Vms.TroubleshootVmListingAsync();

    public Task QuickSnapshotAsync(string vmName) => Snapshots.QuickSnapshotAsync(vmName);

    public Task<Dictionary<string, int>> GetAllSnapshotCountsAsync() =>
        Snapshots.GetAllSnapshotCountsAsync();

    public Task ExportSnapshotAsync(string snapshotId, string exportPath) =>
        Snapshots.ExportSnapshotAsync(snapshotId, exportPath);

    public Task UploadSnapshotAsync(
        string vmName,
        string snapshotName,
        string snapshotId,
        string networkShareRoot
    ) => Snapshots.UploadSnapshotAsync(vmName, snapshotName, snapshotId, networkShareRoot);

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

    public Task CloneVmFromSnapshotAsync(string vmName, string snapshotName, string newVmName) =>
        Import.CloneVmFromSnapshotAsync(vmName, snapshotName, newVmName);

    public Task ResetDiskAsync(string name) => Import.ResetDiskAsync(name);

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

    public Task StopVmIfRunningAsync(string vmName) => Snapshots.StopVmIfRunningAsync(vmName);

    public Task ApplySnapshotAsync(string vmName, string snapshotId) =>
        Snapshots.ApplySnapshotAsync(vmName, snapshotId);
}
