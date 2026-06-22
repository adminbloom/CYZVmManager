namespace VmManager.Contracts.Models;

public class AppSettings
{
    public List<FeedConfiguration> Feeds { get; set; } = new List<FeedConfiguration>();
    public bool HasCompletedSetup { get; set; }

    public string LocalVmPath { get; set; } =
        OperatingSystem.IsWindows() ? @"C:\VMs" : "/var/lib/vmmanager";
    public int DefaultMemoryMb { get; set; } = 4096;
    public int DefaultCpuCount { get; set; } = 4;

    public string DefaultLocale { get; set; } = "";
    public string DefaultKeyboardLayout { get; set; } = "";
    public string DefaultTimezone { get; set; } = "";
    public bool ApplyLocaleOnCreate { get; set; }

    public string DefaultVmUsername { get; set; } = "Administrator";
    public string DefaultVmPassword { get; set; } = "Admin123!";
    public string RdpDomainSuffix { get; set; } = "";

    public string VmBackend { get; set; } = "HyperV";
    public string VmSwitch { get; set; } = "Default Switch";

    public bool RenameComputerToVmName { get; set; } = true;
    public string PostCreationScript { get; set; } = "";
    public string PostStartupScript { get; set; } = "";

    public bool AutoCleanupUnusedNetworks { get; set; } = true;

    /// <summary>
    /// If true, allows executing PowerShell scripts inside VMs via
    /// POST /api/vms/{name}/exec. Requires the vm.exec permission.
    /// Default: false (disabled for security).
    /// </summary>
    public bool AllowExec { get; set; }

    public ProxmoxSettings? Proxmox { get; set; }

    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public string SmtpUsername { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
    public string SmtpFromAddress { get; set; } = "";
    public bool SmtpUseTls { get; set; } = true;
    public bool SmtpEnabled { get; set; }

    public int MaxTotalVms { get; set; }
    public int DefaultUserMaxVms { get; set; }

    public int StaleVmReminderDays { get; set; }

    public MonitoringSettings? Monitoring { get; set; }
}
