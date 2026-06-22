namespace VmManager.Contracts.Models;

public static class Permission
{
    public const string VmCreate = "vm.create";
    public const string VmDelete = "vm.delete";
    public const string VmStart = "vm.start";
    public const string VmStop = "vm.stop";
    public const string VmRename = "vm.rename";
    public const string VmReset = "vm.reset";
    public const string VmApplyLocale = "vm.apply-locale";
    public const string VmViewOwn = "vm.view-own";
    public const string VmViewAll = "vm.view-all";

    public const string SnapshotCreate = "snapshot.create";
    public const string SnapshotRestore = "snapshot.restore";
    public const string SnapshotDelete = "snapshot.delete";
    public const string SnapshotClone = "snapshot.clone";
    public const string SnapshotPush = "snapshot.push";

    public const string CatalogBrowse = "catalog.browse";
    public const string CatalogImport = "catalog.import";
    public const string CatalogDeleteLocal = "catalog.delete-local";

    public const string SettingsView = "settings.view";
    public const string SettingsEditVmDefaults = "settings.edit-vm-defaults";
    public const string SettingsManageFeeds = "settings.manage-feeds";
    public const string SettingsEditScripts = "settings.edit-scripts";

    public const string RdpConnect = "rdp.connect";

    /// <summary>Execute PowerShell scripts inside a VM via POST /api/vms/{name}/exec.
    /// Requires AllowExec=true in settings.json. Included in DefaultUser set.</summary>
    public const string VmExec = "vm.exec";

    public const string UsersManage = "users.manage";

    public const string MonitoringView = "monitoring.view";
    public const string MonitoringManage = "monitoring.manage";

    public const string PermissionClaimType = "VmManager.Permission";

    public static HashSet<string> All { get; } =
    [
        VmCreate,
        VmDelete,
        VmStart,
        VmStop,
        VmRename,
        VmReset,
        VmApplyLocale,
        VmViewOwn,
        VmViewAll,
        SnapshotCreate,
        SnapshotRestore,
        SnapshotDelete,
        SnapshotClone,
        SnapshotPush,
        CatalogBrowse,
        CatalogImport,
        CatalogDeleteLocal,
        SettingsView,
        SettingsEditVmDefaults,
        SettingsManageFeeds,
        SettingsEditScripts,
        RdpConnect,
        VmExec,
        UsersManage,
        MonitoringView,
        MonitoringManage,
    ];

    public static HashSet<string> DefaultUser { get; } =
    [VmViewOwn, VmStart, VmStop, VmCreate, SnapshotCreate, CatalogBrowse, SettingsView, RdpConnect, VmExec];

    public static HashSet<string> Shareable { get; } =
    [VmStart, VmStop, VmReset, RdpConnect, SnapshotCreate, SnapshotRestore];
}
