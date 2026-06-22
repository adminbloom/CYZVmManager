using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VmManager.Agent.Services;
using VmManager.Contracts.Models;

namespace VmManager.Agent.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CatalogController : ControllerBase
{
    private readonly CatalogAggregator _catalogAggregator;
    private readonly ImportService _importService;
    private readonly IVmBackend _backend;
    private readonly INetworkService _networkService;
    private readonly NetworkProvisioningService _networkProvisioningService;
    private readonly NetworkTrackingService _networkTrackingService;
    private readonly SettingsService _settingsService;
    private readonly IVmTrackingService _vmTrackingService;
    private readonly ILocalImageMetadataService _localImageMetadataService;
    private readonly IBackgroundTaskManager _backgroundTaskManager;
    private readonly VmOwnershipService _ownershipService;
    private readonly QuotaService _quotaService;
    private readonly EmailService _emailService;
    private readonly UserService _userService;
    private readonly ILogger<CatalogController> _logger;

    public CatalogController(
        CatalogAggregator catalogAggregator,
        ImportService importService,
        IVmBackend backend,
        INetworkService networkService,
        NetworkProvisioningService networkProvisioningService,
        NetworkTrackingService networkTrackingService,
        SettingsService settingsService,
        IVmTrackingService vmTrackingService,
        ILocalImageMetadataService localImageMetadataService,
        IBackgroundTaskManager backgroundTaskManager,
        VmOwnershipService ownershipService,
        QuotaService quotaService,
        EmailService emailService,
        UserService userService,
        ILogger<CatalogController> logger
    )
    {
        ArgumentNullException.ThrowIfNull(catalogAggregator);
        ArgumentNullException.ThrowIfNull(importService);
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(networkService);
        ArgumentNullException.ThrowIfNull(networkProvisioningService);
        ArgumentNullException.ThrowIfNull(networkTrackingService);
        ArgumentNullException.ThrowIfNull(settingsService);
        ArgumentNullException.ThrowIfNull(vmTrackingService);
        ArgumentNullException.ThrowIfNull(localImageMetadataService);
        ArgumentNullException.ThrowIfNull(backgroundTaskManager);
        ArgumentNullException.ThrowIfNull(ownershipService);
        ArgumentNullException.ThrowIfNull(quotaService);
        ArgumentNullException.ThrowIfNull(emailService);
        ArgumentNullException.ThrowIfNull(userService);
        ArgumentNullException.ThrowIfNull(logger);
        _catalogAggregator = catalogAggregator;
        _importService = importService;
        _backend = backend;
        _networkService = networkService;
        _networkProvisioningService = networkProvisioningService;
        _networkTrackingService = networkTrackingService;
        _settingsService = settingsService;
        _vmTrackingService = vmTrackingService;
        _localImageMetadataService = localImageMetadataService;
        _backgroundTaskManager = backgroundTaskManager;
        _ownershipService = ownershipService;
        _quotaService = quotaService;
        _emailService = emailService;
        _userService = userService;
        _logger = logger;
    }

    [HttpGet]
    [Authorize(Policy = Permission.CatalogBrowse)]
    [ProducesResponseType(typeof(List<VmImage>), 200)]
    public async Task<IActionResult> LoadCatalog(CancellationToken cancellationToken)
    {
        List<VmImage> images = await _catalogAggregator.LoadCatalogAsync();

        AppSettings settings = _settingsService.Load();
        string extractedRoot = Path.Combine(settings.LocalVmPath, "extracted");
        if (!Directory.Exists(extractedRoot))
            return Ok(images);

        Dictionary<string, string> localImagesByKey = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase
        );
        foreach (string dir in Directory.GetDirectories(extractedRoot))
        {
            LocalImageMetadata? meta = _localImageMetadataService.LoadMetadata(dir);
            if (meta == null)
                continue;

            string key =
                (meta.FeedId ?? "") + "|" + (meta.ParentImageId ?? "") + "|" + (meta.Version ?? "");
            localImagesByKey[key] = dir;
        }

        foreach (VmImage img in images)
        {
            foreach (VmImageVersion ver in img.Versions)
            {
                string key =
                    (ver.FeedId ?? "")
                    + "|"
                    + (ver.ParentImageId ?? "")
                    + "|"
                    + (ver.Version ?? "");
                if (localImagesByKey.ContainsKey(key))
                    ver.IsLocallyAvailable = true;
            }
        }

        return Ok(images);
    }

    [HttpGet("local")]
    [Authorize(Policy = Permission.CatalogBrowse)]
    [ProducesResponseType(typeof(List<LocalImage>), 200)]
    public IActionResult GetLocalImages()
    {
        AppSettings settings = _settingsService.Load();
        string extractedDir = Path.Combine(settings.LocalVmPath, "extracted");

        List<LocalImage> locals = new List<LocalImage>();
        if (!Directory.Exists(extractedDir))
            return Ok(locals);

        foreach (string dir in Directory.GetDirectories(extractedDir))
        {
            string[] diskFiles = Directory
                .GetFiles(dir, "*.vhdx", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(dir, "*.qcow2", SearchOption.AllDirectories))
                .ToArray();
            if (diskFiles.Length == 0)
                continue;

            DirectoryInfo dirInfo = new DirectoryInfo(dir);
            long totalSize = diskFiles.Sum(f => new FileInfo(f).Length);

            string displayName = dirInfo.Name;
            string? feedId = null,
                feedUrl = null,
                feedRepo = null;
            string? parentImageId = null,
                parentImageName = null,
                imageVersion = null;

            LocalImageMetadata? meta = _localImageMetadataService.LoadMetadata(dir);
            if (meta != null)
            {
                if (!string.IsNullOrEmpty(meta.Name))
                    displayName = meta.Name;
                feedId = meta.FeedId;
                feedUrl = meta.FeedUrl;
                feedRepo = meta.FeedRepository;
                parentImageId = meta.ParentImageId;
                parentImageName = meta.ParentImageName;
                imageVersion = meta.Version;
            }

            locals.Add(
                new LocalImage
                {
                    Name = displayName,
                    Path = dir,
                    SizeGb = totalSize / 1073741824.0,
                    ExtractedAt = dirInfo.CreationTime,
                    FeedId = feedId,
                    FeedUrl = feedUrl,
                    FeedRepository = feedRepo,
                    ParentImageId = parentImageId,
                    ParentImageName = parentImageName,
                    ImageVersion = imageVersion,
                }
            );
        }

        return Ok(locals.OrderByDescending(l => l.ExtractedAt));
    }

    [HttpDelete("local")]
    [Authorize(Policy = Permission.CatalogDeleteLocal)]
    [ProducesResponseType(204)]
    public IActionResult DeleteLocalImage([FromQuery] string path)
    {
        AppSettings settingsCheck = _settingsService.Load();
        string extractedDir = Path.GetFullPath(
            Path.Combine(settingsCheck.LocalVmPath, "extracted")
        );
        string fullPath = Path.GetFullPath(path);
        if (!fullPath.StartsWith(extractedDir, StringComparison.OrdinalIgnoreCase))
            return BadRequest(
                new { error = "Path must be within the extracted images directory." }
            );

        if (Directory.Exists(fullPath))
        {
            path = fullPath;
            string dirName = Path.GetFileName(path);
            Directory.Delete(path, true);

            AppSettings settings = _settingsService.Load();
            string downloadsDir = Path.Combine(settings.LocalVmPath, "downloads");
            if (Directory.Exists(downloadsDir))
            {
                foreach (string file in Directory.GetFiles(downloadsDir))
                {
                    string fileName = Path.GetFileName(file);
                    if (fileName.StartsWith(dirName, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogInformation("Deleting download file: {File}", file);
                        System.IO.File.Delete(file);
                    }
                }
            }
        }
        return NoContent();
    }

    [HttpPost("import")]
    [Authorize(Policy = Permission.CatalogImport)]
    [ProducesResponseType(typeof(object), 202)]
    public IActionResult ImportVersion([FromBody] ImportRequest request)
    {
        _logger.LogInformation("Starting import for {VersionRef}", request.VersionRef);

        AppSettings settings = _settingsService.Load();

        IBackgroundTask task = _backgroundTaskManager.StartTask(
            "Importing " + request.VersionRef,
            async ctx =>
            {
                string downloadUrl = await _catalogAggregator.GetDownloadUrlAsync(
                    request.VersionRef
                );

                System.Net.Http.Headers.AuthenticationHeaderValue? auth = null;
                if (CatalogAggregator.IsNexusVersion(request.VersionRef))
                    auth = _catalogAggregator.GetNexusAuthHeader();
                else if (!CatalogAggregator.IsLocalVersion(request.VersionRef))
                    auth = _catalogAggregator.GetAuthHeader();

                string storageId = Convert
                    .ToHexString(
                        System.Security.Cryptography.SHA256.HashData(
                            System.Text.Encoding.UTF8.GetBytes(request.VersionRef)
                        )
                    )[..12]
                    .ToLowerInvariant();

                string downloadPath = Path.Combine(
                    settings.LocalVmPath,
                    "downloads",
                    storageId + ".box"
                );
                Directory.CreateDirectory(Path.GetDirectoryName(downloadPath)!);

                ctx.ReportProgress(0, "Downloading...");
                await _importService.DownloadWithProgressAsync(
                    downloadUrl,
                    downloadPath,
                    new Progress<DownloadProgress>(p =>
                    {
                        double speedMb = p.SpeedBytesPerSec / 1024.0 / 1024.0;
                        double dlMb = p.DownloadedBytes / 1024.0 / 1024.0;
                        double totalMb = p.TotalBytes / 1024.0 / 1024.0;
                        string status = p.Eta.HasValue
                            ? string.Format(
                                "Downloading: {0:F0}/{1:F0} MB ({2:F1} MB/s, ~{3:mm\\:ss} remaining)",
                                dlMb,
                                totalMb,
                                speedMb,
                                p.Eta.Value
                            )
                            : string.Format("Downloading: {0:F0} MB ({1:F1} MB/s)", dlMb, speedMb);
                        ctx.ReportProgress(p.Percent / 200.0, status);
                    }),
                    ctx.Token,
                    auth
                );

                string extractPath = Path.Combine(settings.LocalVmPath, "extracted", storageId);
                ctx.ReportProgress(0.5, "Extracting...");
                await _importService.ExtractAsync(
                    downloadPath,
                    extractPath,
                    new Progress<double>(pct =>
                    {
                        ctx.ReportProgress(
                            0.5 + pct / 2.0,
                            string.Format("Extracting: {0:F0}%", pct)
                        );
                    }),
                    ctx.Token
                );

                if (request.Version != null)
                    _localImageMetadataService.SaveMetadata(extractPath, request.Version);

                // On Linux: convert VHDX to QCOW2 in-place and delete the VHDX
                if (OperatingSystem.IsLinux())
                {
                    string? vhdxFile = Directory
                        .GetFiles(extractPath, "*.vhdx", SearchOption.AllDirectories)
                        .Concat(
                            Directory.GetFiles(extractPath, "*.avhdx", SearchOption.AllDirectories)
                        )
                        .FirstOrDefault();

                    bool hasQcow2 = Directory
                        .GetFiles(extractPath, "*.qcow2", SearchOption.AllDirectories)
                        .Any();

                    if (vhdxFile != null && !hasQcow2)
                    {
                        string qcow2File = Path.ChangeExtension(vhdxFile, ".qcow2");
                        long vhdxSize = new FileInfo(vhdxFile).Length;

                        ctx.ReportProgress(0.9, "Converting VHDX to QCOW2...");
                        _logger.LogInformation(
                            "Converting VHDX in-place: {Source} -> {Dest}",
                            vhdxFile,
                            qcow2File
                        );

                        Task convertTask = Task.Run(async () =>
                        {
                            Process proc = new Process
                            {
                                StartInfo = new ProcessStartInfo
                                {
                                    FileName = "qemu-img",
                                    Arguments = $"convert -O qcow2 \"{vhdxFile}\" \"{qcow2File}\"",
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                },
                            };
                            proc.Start();
                            await proc.WaitForExitAsync(ctx.Token);
                            if (proc.ExitCode != 0)
                            {
                                string stderr = await proc.StandardError.ReadToEndAsync();
                                throw new InvalidOperationException(
                                    $"qemu-img convert failed: {stderr}"
                                );
                            }
                        });

                        while (!convertTask.IsCompleted)
                        {
                            await Task.Delay(2000, ctx.Token);
                            if (System.IO.File.Exists(qcow2File))
                            {
                                long currentSize = new FileInfo(qcow2File).Length;
                                double pct = Math.Min((double)currentSize / vhdxSize * 100, 99);
                                ctx.ReportProgress(0.9 + pct / 1000.0, $"Converting: {pct:F0}%");
                            }
                        }

                        await convertTask; // propagate exceptions

                        System.IO.File.Delete(vhdxFile);
                        _logger.LogInformation(
                            "VHDX converted and deleted. QCOW2: {Path}",
                            qcow2File
                        );
                    }
                }

                ctx.ReportProgress(1.0, "Complete");
            }
        );

        return Accepted(new { taskId = task.Id, title = task.Title });
    }

    [HttpPost("create-vm")]
    [Authorize(Policy = Permission.VmCreate)]
    [ProducesResponseType(typeof(object), 202)]
    public async Task<IActionResult> CreateVm([FromBody] CreateVmRequest request)
    {
        string currentUser = User.Identity?.Name ?? "admin";

        QuotaCheckResult quotaCheck = await _quotaService.CheckCanCreateVmAsync(currentUser);
        if (!quotaCheck.Allowed)
            return BadRequest(new { error = quotaCheck.Reason });

        _logger.LogInformation(
            "Creating VM {VmName} from {ExtractedFolder}, Origin: FeedId={FeedId}, FeedUrl={FeedUrl}, Repo={Repo}, ImageId={ImageId}",
            request.Name,
            request.ExtractedFolder,
            request.Origin?.FeedId ?? "(null)",
            request.Origin?.FeedUrl ?? "(null)",
            request.Origin?.Repository ?? "(null)",
            request.Origin?.ImageId ?? "(null)"
        );

        AppSettings settings = _settingsService.Load();

        IBackgroundTask task = _backgroundTaskManager.StartTask(
            "Creating VM " + request.Name,
            async ctx =>
            {
                List<(string SwitchName, VmNetworkAdapter Config)>? networkMappings = null;
                if (request.Networks != null && request.Networks.Count > 0)
                {
                    ctx.ReportProgress(-1, "Provisioning networks...");
                    networkMappings = await _networkProvisioningService.EnsureNetworksAsync(
                        request.Networks,
                        request.Name,
                        request.Origin?.FeedId
                    );
                }

                try
                {
                    ctx.ReportProgress(-1, "Importing VM...");
                    await _backend.ImportVmAsync(
                        request.ExtractedFolder,
                        settings.LocalVmPath,
                        request.MemoryMb,
                        request.CpuCount,
                        request.Name,
                        skipDefaultNetwork: networkMappings != null && networkMappings.Count > 0,
                        onStatus: status => ctx.ReportProgress(-1, status),
                        cancellationToken: ctx.Token,
                        vmSwitch: settings.VmSwitch
                    );
                }
                catch (OrphanedVmException ex)
                {
                    if (networkMappings != null)
                        _networkTrackingService.DecrementReferences(request.Name);
                    NotifyOrphanedVm(ex);
                    throw;
                }
                catch
                {
                    if (networkMappings != null)
                        _networkTrackingService.DecrementReferences(request.Name);
                    throw;
                }

                _vmTrackingService.TrackVm(request.Name, request.Origin);
                _ownershipService.SetOwner(request.Name, currentUser);

                if (networkMappings != null && networkMappings.Count > 0)
                {
                    ctx.ReportProgress(-1, "Configuring network adapters...");
                    await _networkService.ConfigureVmAdaptersAsync(request.Name, networkMappings);
                }

                bool applyLocale =
                    settings.ApplyLocaleOnCreate
                    && !string.IsNullOrWhiteSpace(settings.DefaultLocale);
                bool needsPostCreation =
                    settings.RenameComputerToVmName
                    || !string.IsNullOrWhiteSpace(settings.PostCreationScript);

                if (
                    (applyLocale || needsPostCreation)
                    && !string.IsNullOrWhiteSpace(settings.DefaultVmUsername)
                    && !string.IsNullOrWhiteSpace(settings.DefaultVmPassword)
                )
                {
                    try
                    {
                        ctx.ReportProgress(-1, "Configuring VM (single boot)...");
                        ctx.Log(
                            "Combined configuration: locale="
                                + (applyLocale ? settings.DefaultLocale : "skip")
                                + ", rename="
                                + settings.RenameComputerToVmName
                                + ", postScript="
                                + (!string.IsNullOrWhiteSpace(settings.PostCreationScript))
                        );
                        await _backend.ConfigureAndFinalizeAsync(
                            request.Name,
                            settings.DefaultVmUsername,
                            settings.DefaultVmPassword,
                            applyLocale ? settings.DefaultLocale : null,
                            applyLocale ? settings.DefaultKeyboardLayout : null,
                            applyLocale ? settings.DefaultTimezone : null,
                            settings.RenameComputerToVmName,
                            settings.PostCreationScript,
                            onStatus: status => ctx.ReportProgress(-1, status)
                        );
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "VM configuration failed for {VmName}", request.Name);
                        ctx.Log("Configuration failed: " + ex.Message);
                    }
                }
                else
                {
                    ctx.ReportProgress(-1, "Creating base snapshot...");
                    await _backend.CreateSnapshotAsync(request.Name, "Base");
                }

                List<VmNetworkAdapter> staticIpAdapters =
                    request.Networks?.Where(a => !string.IsNullOrEmpty(a.StaticIp)).ToList() ?? [];
                if (staticIpAdapters.Count > 0)
                {
                    ctx.ReportProgress(-1, "Configuring network addresses...");
                    await _networkService.ConfigureGuestIpAsync(
                        request.Name,
                        settings.DefaultVmUsername,
                        settings.DefaultVmPassword,
                        staticIpAdapters
                    );
                }

                _ = SendVmCreatedEmailAsync(currentUser, request.Name);
                _ = _quotaService.CheckAndNotifyApproachingLimitAsync(currentUser);

                ctx.ReportProgress(1.0, "Complete");
            }
        );

        return Accepted(new { taskId = task.Id, title = task.Title });
    }

    private async Task SendVmCreatedEmailAsync(string username, string vmName)
    {
        try
        {
            string? email = GetUserEmail(username);
            if (string.IsNullOrWhiteSpace(email))
                return;

            string body =
                $@"
<h2>VM Ready</h2>
<p>Your VM <b>{vmName}</b> has been created and is ready to use.</p>
<p>You can connect to it from the VmManager client.</p>";

            await _emailService.SendAsync(email, "VM Ready: " + vmName, body);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send VM created email for {VmName}", vmName);
        }
    }

    private void NotifyOrphanedVm(OrphanedVmException ex)
    {
        try
        {
            if (!_emailService.IsConfigured)
                return;
            AppSettings settings = _settingsService.Load();
            string? notifyEmail = settings.Monitoring?.DefaultNotificationEmail;
            if (string.IsNullOrWhiteSpace(notifyEmail))
                return;
            _ = _emailService.SendAsync(
                notifyEmail,
                "[VmManager] Orphaned VM requires manual cleanup",
                "<h2>Orphaned VM</h2>"
                    + "<p>VM creation failed and the VM could not be automatically deleted from Proxmox.</p>"
                    + "<p><b>VM Name:</b> "
                    + ex.VmName
                    + "<br/>"
                    + "<b>VMID:</b> "
                    + ex.VmId
                    + "<br/>"
                    + "<b>Error:</b> "
                    + ex.Message
                    + "</p>"
                    + "<p>Please delete VMID "
                    + ex.VmId
                    + " manually in the Proxmox web UI.</p>"
            );
        }
        catch (Exception emailEx)
        {
            _logger.LogWarning(emailEx, "Failed to send orphaned VM notification");
        }
    }

    private string? GetUserEmail(string username)
    {
        UserAccount? user = _userService.GetByUsername(username);
        if (user == null)
            return null;
        if (user.IsAdmin)
            return string.IsNullOrWhiteSpace(user.Email) ? null : user.Email;
        return EmailValidator.IsValid(user.Username) ? user.Username : null;
    }
}
