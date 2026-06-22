using VmManager.Contracts.Models;

namespace VmManager.Contracts.Interfaces;

public interface IVmBackend
{
    Task<List<VmInstance>> GetVmsAsync();
    Task StartVmAsync(string name);
    Task StopVmAsync(string name);
    Task DeleteVmAsync(string name);
    Task RenameVmAsync(string currentName, string newName);
    Task<bool> ResetVmAsync(string name);
    Task<List<VmSnapshot>> GetSnapshotsAsync(string vmName);
    Task CreateSnapshotAsync(string vmName, string snapshotName);
    Task RestoreSnapshotAsync(string vmName, string snapshotId);
    Task DeleteSnapshotAsync(string vmName, string snapshotId);
    Task ImportVmAsync(
        string extractedFolder,
        string localVmPath,
        int memoryMb,
        int cpuCount,
        string? vmName = null,
        bool skipDefaultNetwork = false,
        Action<string>? onStatus = null,
        CancellationToken cancellationToken = default,
        string? vmSwitch = null
    );
    Task ConnectToVmAsync(string vmName, string username = "", string password = "");
    Task ExportSnapshotAsync(string snapshotId, string destDir);
    Task ConfigureLocaleAsync(
        string vmName,
        string username,
        string password,
        string locale = "de-DE",
        string keyboardLayout = "00000407",
        string timezone = "",
        Action<string>? onStatus = null
    );
    Task RunPostCreationAsync(
        string vmName,
        string username,
        string password,
        bool renameComputer,
        string? postCreationScript = null,
        Action<string>? onStatus = null
    );
    async Task ConfigureAndFinalizeAsync(
        string vmName,
        string username,
        string password,
        string? locale,
        string? keyboardLayout,
        string? timezone,
        bool renameComputer,
        string? postCreationScript,
        Action<string>? onStatus = null
    )
    {
        if (!string.IsNullOrWhiteSpace(locale))
        {
            await ConfigureLocaleAsync(
                vmName,
                username,
                password,
                locale!,
                keyboardLayout ?? "00000407",
                timezone ?? "",
                onStatus
            );
        }

        if (renameComputer || !string.IsNullOrWhiteSpace(postCreationScript))
        {
            await RunPostCreationAsync(
                vmName,
                username,
                password,
                renameComputer,
                postCreationScript,
                onStatus
            );
        }

        await CreateSnapshotAsync(vmName, "Base");
    }
    Task CloneVmFromSnapshotAsync(string vmName, string snapshotName, string newVmName);
    Task ResetDiskAsync(string name);
    Task<string?> TroubleshootAsync();
}
