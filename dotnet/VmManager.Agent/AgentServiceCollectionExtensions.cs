using VmManager.Agent.Services;
using VmManager.Agent.Services.Monitoring;
using VmManager.Agent.Services.Monitoring.Checks;
using VmManager.Agent.Services.Rdp;
using VmManager.Backends.HyperV;
using VmManager.Backends.Kvm;
using VmManager.Backends.Proxmox;
using VmManager.Catalog.Shared;
using VmManager.Contracts.Interfaces;
using VmManager.Contracts.Models;

namespace VmManager.Agent;

public static class AgentServiceCollectionExtensions
{
    public static IServiceCollection AddAgentServices(
        this IServiceCollection services,
        string? backendOverride = null
    )
    {
        services.AddSingleton<IAppPaths, AppPaths>();
        services.AddSingleton<TempTracker>();
        services.AddSingleton<ITempTracker>(sp => sp.GetRequiredService<TempTracker>());
        services.AddSingleton<VmTrackingService>();
        services.AddSingleton<IVmTrackingService>(sp => sp.GetRequiredService<VmTrackingService>());
        services.AddSingleton<ILocalImageMetadataService, LocalImageMetadataService>();
        services.AddSingleton<BackgroundTaskManager>();
        services.AddSingleton<IBackgroundTaskManager>(sp =>
            sp.GetRequiredService<BackgroundTaskManager>()
        );
        services.AddSingleton<SnapshotPushService>();
        services.AddSingleton<FeedResolutionService>();

        if (string.Equals(backendOverride, "Fake", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<IVmBackend, FakeVmBackend>();
            services.AddSingleton<IVmIpResolver>(sp => new FakeIpResolver());
            services.AddSingleton<IVmExecService, FakeExecService>();
        }
        else if (string.Equals(backendOverride, "Proxmox", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<ProxmoxApiClient>(sp =>
            {
                SettingsService settingsService = sp.GetRequiredService<SettingsService>();
                ProxmoxSettings proxmox =
                    settingsService.Load().Proxmox
                    ?? throw new InvalidOperationException(
                        "Proxmox backend selected but no Proxmox settings configured in settings.json"
                    );
                return new ProxmoxApiClient(
                    proxmox,
                    sp.GetRequiredService<ILogger<ProxmoxApiClient>>(),
                    () => settingsService.Load().Proxmox ?? proxmox
                );
            });
            services.AddSingleton<ProxmoxIpResolver>();
            services.AddSingleton<IVmIpResolver>(sp => sp.GetRequiredService<ProxmoxIpResolver>());
            services.AddSingleton<ProxmoxTemplateRegistry>();
            services.AddSingleton<IVmExecService, NotImplementedExecService>();
        }
        else if (OperatingSystem.IsWindows())
        {
            services.AddSingleton<VmIpResolver>();
            services.AddSingleton<IVmIpResolver>(sp => sp.GetRequiredService<VmIpResolver>());
            services.AddSingleton<HyperVExecService>();
            services.AddSingleton<IVmExecService>(sp => sp.GetRequiredService<HyperVExecService>());
        }
        else if (OperatingSystem.IsLinux())
        {
            services.AddSingleton<KvmIpResolver>();
            services.AddSingleton<IVmIpResolver>(sp => sp.GetRequiredService<KvmIpResolver>());
            services.AddSingleton<IVmExecService, NotImplementedExecService>();
        }

        services.AddSingleton<RdpTcpRelay>();
        services.AddSingleton<RdpSessionStore>();
        services.AddSingleton<RdpProxyListener>();
        services.AddSingleton<CertificateFactory>();
        services.AddSingleton<ClientCredSspHandler>();
        services.AddSingleton<VmCredSspHandler>();
        services.AddSingleton<VmCredentialStore>();
        services.AddSingleton<RdpCredSspConnectionHandler>();
        services.AddSingleton<NetworkTrackingService>();
        services.AddSingleton<NetworkProvisioningService>();

        services.AddSingleton<UserService>();
        services.AddSingleton<VmOwnershipService>();
        services.AddSingleton<VmSharingService>();
        services.AddSingleton<AuthorizationService>();
        services.AddSingleton<EmailService>();
        services.AddSingleton<QuotaService>();
        services.AddHostedService<StaleVmReminderService>();

        services.AddSingleton<AlertStore>();
        services.AddSingleton<AlertNotifier>();
        services.AddSingleton<MetricsCache>();
        services.AddSingleton<VmStopTracker>();
        services.AddSingleton<LoginAttemptTracker>();
        services.AddSingleton<MonitoringService>();
        services.AddHostedService<MonitoringService>(sp =>
            sp.GetRequiredService<MonitoringService>()
        );
        services.AddSingleton<IMonitoringCheck, VmStateMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, VmPortMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, VmUptimeMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, SnapshotDepthMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, HostResourceMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, StorageMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, DiskHealthMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, AgentHealthMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, CapacityMonitorCheck>();
        services.AddSingleton<IMonitoringCheck, LoginMonitorCheck>();

        return services;
    }
}
