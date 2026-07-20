using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Serilog;

namespace VmManager.Agent.Services;

public class CertManagerService : IHostedService, IDisposable
{
    private const int CertRefreshIntervalSec = 720;   // 12 min (80% of 15-min validity)
    private const int CrlRefreshIntervalSec = 900;     // 15 min
    private const int MaxRetries = 3;
    private const int RetryBackoffBaseSec = 2;

    private readonly SettingsService _settingsService;
    private readonly ILogger<CertManagerService> _logger;
    private Timer? _certTimer;
    private Timer? _crlTimer;
    private readonly object _lock = new();
    private volatile bool _isCertValid;
    private byte[]? _crlBytes;
    private byte[]? _caCertBytes;

    public bool IsCertValid => _isCertValid;

    public string GetServerCertPath() => _settingsService.Load().ServerCertPath;
    public string GetServerKeyPath() => _settingsService.Load().ServerKeyPath;
    public string GetCaCertPath() => _settingsService.Load().CaCertPath;
    public string GetCrlPath() => _settingsService.Load().CrlPath;

    public byte[]? GetCrlBytes()
    {
        lock (_lock)
            return _crlBytes;
    }

    public byte[]? GetCaCertBytes()
    {
        lock (_lock)
            return _caCertBytes;
    }

    public CertManagerService(SettingsService settingsService, ILogger<CertManagerService> logger)
    {
        _settingsService = settingsService;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = _settingsService.Load();
        Directory.CreateDirectory(Path.GetDirectoryName(settings.ServerCertPath)!);

        if (!settings.EnableTls || string.IsNullOrEmpty(settings.CertServerUrl))
        {
            _logger.LogInformation("CertManagerService: TLS disabled, skipping cert fetch");
            return;
        }

        await EnsureCaCertAsync(settings);

        bool certOk = await FetchCertAsync(settings);
        if (!certOk)
        {
            _logger.LogError("CertManagerService: initial cert fetch failed - fail-closed");
            throw new InvalidOperationException("CertManagerService: initial cert fetch failed");
        }

        await FetchCrlAsync(settings);
        LoadCaCertBytes();

        _certTimer = new Timer(
            _ => _ = RefreshCertAsync(),
            null,
            TimeSpan.FromSeconds(CertRefreshIntervalSec),
            TimeSpan.FromSeconds(CertRefreshIntervalSec)
        );
        _crlTimer = new Timer(
            _ => _ = RefreshCrlAsync(),
            null,
            TimeSpan.FromSeconds(CrlRefreshIntervalSec),
            TimeSpan.FromSeconds(CrlRefreshIntervalSec)
        );

        _logger.LogInformation("CertManagerService started (cert refresh={Sec}s, crl refresh={CrlSec}s)",
            CertRefreshIntervalSec, CrlRefreshIntervalSec);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _certTimer?.Change(Timeout.Infinite, 0);
        _crlTimer?.Change(Timeout.Infinite, 0);
        _logger.LogInformation("CertManagerService stopped");
        await Task.CompletedTask;
    }

    private async Task EnsureCaCertAsync(AppSettings settings)
    {
        if (File.Exists(settings.CaCertPath) && new FileInfo(settings.CaCertPath).Length > 0)
        {
            LoadCaCertBytes();
            return;
        }

        var provider = CertProviderFactory.Create(
            settings.CertProvider,
            settings.CertServerUrl,
            settings.CertServerAuthToken,
            settings.CaCertPath,
            settings.CrlUrl,
            _logger,
            settings.StepCaTokenCommand
        );

        try
        {
            string? caPem = await provider.FetchCaCertAsync();
            if (!string.IsNullOrWhiteSpace(caPem))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(settings.CaCertPath)!);
                File.WriteAllText(settings.CaCertPath, caPem);
                lock (_lock)
                    _caCertBytes = System.Text.Encoding.UTF8.GetBytes(caPem);
                _logger.LogInformation("CertManagerService: downloaded CA cert to {Path}", settings.CaCertPath);
                return;
            }
        }
        catch (Exception e)
        {
            _logger.LogWarning("CertManagerService: CA download failed: {Error}", e.Message);
        }

        if (!File.Exists(settings.CaCertPath))
        {
            throw new InvalidOperationException(
                $"CA cert missing at {settings.CaCertPath} and download from cert server failed"
            );
        }
    }

    private async Task<bool> FetchCertAsync(AppSettings settings)
    {
        var provider = CertProviderFactory.Create(
            settings.CertProvider,
            settings.CertServerUrl,
            settings.CertServerAuthToken,
            settings.CaCertPath,
            settings.CrlUrl,
            _logger,
            settings.StepCaTokenCommand
        );

        // Phase 1: Try renewal via mTLS if we already have a cert+key
        if (File.Exists(settings.ServerCertPath) && File.Exists(settings.ServerKeyPath))
        {
            try
            {
                string existingCert = File.ReadAllText(settings.ServerCertPath);
                string existingKey = File.ReadAllText(settings.ServerKeyPath);
                var renewResult = await provider.RenewCertAsync(existingCert, existingKey);
                if (renewResult.Valid)
                {
                    lock (_lock)
                    {
                        File.WriteAllText(settings.ServerCertPath, renewResult.CertPem);
                        // Key stays the same for renewal
                        _isCertValid = true;
                    }
                    _logger.LogInformation("CertManagerService: cert renewed via mTLS /renew, expiry={Expiry}",
                        renewResult.Expiry);
                    return true;
                }
                _logger.LogWarning("CertManagerService: mTLS renewal failed, falling back to bootstrap");
            }
            catch (Exception e)
            {
                _logger.LogWarning("CertManagerService: mTLS renewal exception, falling back to bootstrap: {Error}", e.Message);
            }
        }

        // Phase 2: Bootstrap via CSR + OTT (one-time token)
        string lastErr = "";
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                var sanIps = CertProviderFactory.GetAgentLanIps();
                var (csrPem, keyPem) = CertProviderFactory.GenerateCsr("bloomce-agent", sanIps: sanIps);
                var result = await provider.SignCsrAsync(csrPem, sanIps: sanIps);

                if (result.Valid)
                {
                    lock (_lock)
                    {
                        File.WriteAllText(settings.ServerCertPath, result.CertPem);
                        File.WriteAllText(settings.ServerKeyPath, keyPem);
                        _isCertValid = true;
                    }
                    _logger.LogInformation("CertManagerService: fetched server cert via CSR bootstrap, expiry={Expiry}",
                        result.Expiry);
                    return true;
                }
                lastErr = "sign_csr returned invalid result";
            }
            catch (Exception e)
            {
                lastErr = e.Message;
            }
            if (attempt < MaxRetries - 1)
                await Task.Delay(TimeSpan.FromSeconds(RetryBackoffBaseSec * Math.Pow(2, attempt) + Random.Shared.NextDouble()));
        }

        // Fallback to legacy /issue-cert endpoint via provider abstraction
        _logger.LogWarning("CertManagerService: CSR-based issuance failed, falling back to /issue-cert: {Error}", lastErr);
        try
        {
            var certResult = await provider.GetCertAsync("bloomce-agent");
            if (certResult.Valid)
            {
                lock (_lock)
                {
                    File.WriteAllText(settings.ServerCertPath, certResult.CertPem);
                    File.WriteAllText(settings.ServerKeyPath, certResult.KeyPem);
                    _isCertValid = true;
                }
                _logger.LogInformation("CertManagerService: fetched server cert via legacy /issue-cert");
                return true;
            }
            lastErr = "Legacy get_cert returned invalid result";
        }
        catch (Exception e)
        {
            lastErr = $"Legacy fallback failed: {e.Message}";
        }

        _logger.LogError("CertManagerService: failed to fetch cert after renewal + CSR + legacy fallback: {Error}",
            lastErr);
        lock (_lock)
            _isCertValid = false;
        return false;
    }

    private async Task FetchCrlAsync(AppSettings settings)
    {
        var provider = CertProviderFactory.Create(
            settings.CertProvider,
            settings.CertServerUrl,
            settings.CertServerAuthToken,
            settings.CaCertPath,
            settings.CrlUrl,
            _logger,
            settings.StepCaTokenCommand
        );

        string lastErr = "";
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                string? crlPem = await provider.FetchCrlAsync();
                if (crlPem != null)
                {
                    byte[] crlData = System.Text.Encoding.UTF8.GetBytes(crlPem);
                    lock (_lock)
                    {
                        File.WriteAllBytes(settings.CrlPath, crlData);
                        _crlBytes = crlData;
                    }
                    _logger.LogInformation("CertManagerService: fetched CRL ({Bytes} bytes)", crlData.Length);
                    return;
                }
                lastErr = "provider returned null";
            }
            catch (Exception e)
            {
                lastErr = e.Message;
            }
            if (attempt < MaxRetries - 1)
                await Task.Delay(TimeSpan.FromSeconds(RetryBackoffBaseSec * Math.Pow(2, attempt) + Random.Shared.NextDouble()));
        }
        _logger.LogWarning("CertManagerService: failed to fetch CRL after {Retries} retries: {Error}",
            MaxRetries, lastErr);
        if (!settings.FailOpenAllowed)
        {
            _logger.LogError("CertManagerService: fail-open not allowed, clearing CRL and marking invalid");
            lock (_lock)
            {
                _crlBytes = null;
            }
            throw new InvalidOperationException($"CRL fetch failed and fail-open not allowed: {lastErr}");
        }
    }

    private void LoadCaCertBytes()
    {
        try
        {
            var settings = _settingsService.Load();
            if (File.Exists(settings.CaCertPath))
            {
                lock (_lock)
                    _caCertBytes = File.ReadAllBytes(settings.CaCertPath);
            }
        }
        catch (Exception e)
        {
            _logger.LogWarning("CertManagerService: failed to load CA cert bytes: {Error}", e.Message);
        }
    }

    private async Task RefreshCertAsync()
    {
        var settings = _settingsService.Load();
        if (await FetchCertAsync(settings))
            _logger.LogInformation("CertManagerService: cert refreshed");
    }

    private async Task RefreshCrlAsync()
    {
        var settings = _settingsService.Load();
        await FetchCrlAsync(settings);
    }

    public void Dispose()
    {
        _certTimer?.Dispose();
        _crlTimer?.Dispose();
    }

}
