using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Serilog;

namespace VmManager.Agent.Services;

// -------------------------------------------------------------------------
// CertLifecycleState - states for the cert lifecycle state machine.
// See mtls_client_spec.md Section 11 for the full state machine definition.
// -------------------------------------------------------------------------
public enum CertLifecycleState
{
    NoCert,
    HaveValid,
    Renewing,
    Bootstrapping
}

public enum CertAction
{
    Wait,
    Renew,
    Bootstrap
}

// -------------------------------------------------------------------------
// CertLifecycle - implements the 4-state cert lifecycle state machine.
// -------------------------------------------------------------------------
public class CertLifecycle
{
    private static readonly int[] BackoffSchedule = { 30, 60, 120, 300 };
    private CertLifecycleState _state = CertLifecycleState.NoCert;
    private int _backoffAttempt;
    private readonly Random _rng = new();

    public CertLifecycleState State => _state;
    public int BackoffAttempt => _backoffAttempt;

    public CertAction Tick(string certPem)
    {
        switch (_state)
        {
            case CertLifecycleState.NoCert:
                _state = CertLifecycleState.Bootstrapping;
                return CertAction.Bootstrap;

            case CertLifecycleState.HaveValid:
                if (IsCertPemExpired(certPem))
                {
                    _state = CertLifecycleState.Bootstrapping;
                    return CertAction.Bootstrap;
                }
                _state = CertLifecycleState.Renewing;
                return CertAction.Renew;

            case CertLifecycleState.Renewing:
            case CertLifecycleState.Bootstrapping:
                return CertAction.Wait;

            default:
                return CertAction.Wait;
        }
    }

    public void OnSuccess()
    {
        if (_backoffAttempt > 0)
            Log.Information("CertManagerService: cert lifecycle recovered after {Attempts} failed attempts", _backoffAttempt);
        _backoffAttempt = 0;
        _state = CertLifecycleState.HaveValid;
    }

    public void OnFailure(bool certWasExpired)
    {
        _backoffAttempt++;
        if (_state == CertLifecycleState.Renewing)
        {
            _state = certWasExpired ? CertLifecycleState.Bootstrapping : CertLifecycleState.HaveValid;
        }
        // if Bootstrapping, stay in Bootstrapping (retry with backoff)
    }

    public int GetWaitSeconds(int rotationIntervalSec)
    {
        if (_backoffAttempt > 0)
        {
            int idx = Math.Min(_backoffAttempt - 1, BackoffSchedule.Length - 1);
            return BackoffSchedule[idx] + _rng.Next(0, 61);
        }
        return rotationIntervalSec + _rng.Next(0, 61);
    }

    public void Reset()
    {
        _state = CertLifecycleState.NoCert;
        _backoffAttempt = 0;
    }

    private static bool IsCertPemExpired(string certPem)
    {
        if (string.IsNullOrWhiteSpace(certPem))
            return true;
        try
        {
            using var cert = new X509Certificate2(System.Text.Encoding.UTF8.GetBytes(certPem));
            return DateTime.UtcNow >= cert.NotAfter;
        }
        catch
        {
            return true;
        }
    }
}

public class CertManagerService : IHostedService, IDisposable
{
    private const int CertRefreshIntervalSec = 720;   // 12 min (80% of 15-min validity)
    private const int CrlRefreshIntervalSec = 900;     // 15 min
    private const int MaxRetries = 3;
    private const int RetryBackoffBaseSec = 2;

    private readonly SettingsService _settingsService;
    private readonly ILogger<CertManagerService> _logger;
    private Timer? _crlTimer;
    private Task? _certRotationTask;
    private CancellationTokenSource? _certCts;
    private readonly CertLifecycle _lifecycle = new();
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

        _lifecycle.OnSuccess();

        await FetchCrlAsync(settings);
        LoadCaCertBytes();

        _certCts = new CancellationTokenSource();
        _certRotationTask = Task.Run(() => CertRotationLoopAsync(_certCts.Token));

        _crlTimer = new Timer(
            _ => _ = RefreshCrlAsync(),
            null,
            TimeSpan.FromSeconds(CrlRefreshIntervalSec),
            TimeSpan.FromSeconds(CrlRefreshIntervalSec)
        );

        _logger.LogInformation("CertManagerService started (cert lifecycle state machine, crl refresh={CrlSec}s)",
            CrlRefreshIntervalSec);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _certCts?.Cancel();
        try
        {
            if (_certRotationTask != null)
                await _certRotationTask;
        }
        catch (OperationCanceledException) { }
        _crlTimer?.Change(Timeout.Infinite, 0);
        _logger.LogInformation("CertManagerService stopped");
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
                var sanDns = new List<string> { "bloomce-agent" };
                var (csrPem, keyPem) = CertProviderFactory.GenerateCsr(
                    "bloomce-agent", sanIps: sanIps, sanDns: sanDns);
                var result = await provider.SignCsrAsync(csrPem, sanIps: sanIps, sanDns: sanDns);

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

    private async Task<bool> RenewCertAsync(AppSettings settings)
    {
        if (!File.Exists(settings.ServerCertPath) || !File.Exists(settings.ServerKeyPath))
            return false;

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
            string existingCert = File.ReadAllText(settings.ServerCertPath);
            string existingKey = File.ReadAllText(settings.ServerKeyPath);
            var renewResult = await provider.RenewCertAsync(existingCert, existingKey);
            if (renewResult.Valid)
            {
                lock (_lock)
                {
                    File.WriteAllText(settings.ServerCertPath, renewResult.CertPem);
                    _isCertValid = true;
                }
                _logger.LogInformation("CertManagerService: cert renewed via mTLS /renew, expiry={Expiry}",
                    renewResult.Expiry);
                return true;
            }
        }
        catch (Exception e)
        {
            _logger.LogWarning("CertManagerService: mTLS renewal failed: {Error}", e.Message);
        }
        return false;
    }

    private async Task<bool> BootstrapCertAsync(AppSettings settings)
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
                var sanIps = CertProviderFactory.GetAgentLanIps();
                var sanDns = new List<string> { "bloomce-agent" };
                var (csrPem, keyPem) = CertProviderFactory.GenerateCsr(
                    "bloomce-agent", sanIps: sanIps, sanDns: sanDns);
                var result = await provider.SignCsrAsync(csrPem, sanIps: sanIps, sanDns: sanDns);

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
        }
        catch (Exception e)
        {
            _logger.LogError("CertManagerService: legacy fallback failed: {Error}", e.Message);
        }

        lock (_lock)
            _isCertValid = false;
        return false;
    }

    private async Task CertRotationLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            int waitSec = _lifecycle.GetWaitSeconds(CertRefreshIntervalSec);
            _logger.LogDebug("CertManagerService: lifecycle state={State}, waiting {Wait}s",
                _lifecycle.State, waitSec);

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(waitSec), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (ct.IsCancellationRequested)
                break;

            var settings = _settingsService.Load();
            string certPem = File.Exists(settings.ServerCertPath)
                ? File.ReadAllText(settings.ServerCertPath)
                : "";

            CertAction action = _lifecycle.Tick(certPem);
            bool success = false;

            switch (action)
            {
                case CertAction.Renew:
                    success = await RenewCertAsync(settings);
                    if (!success)
                    {
                        bool wasExpired = IsCertPemExpired(certPem);
                        _lifecycle.OnFailure(wasExpired);
                        if (wasExpired)
                        {
                            _logger.LogWarning("CertManagerService: cert expired, falling back to bootstrap");
                            success = await BootstrapCertAsync(settings);
                            if (success)
                                _lifecycle.OnSuccess();
                        }
                    }
                    else
                    {
                        _lifecycle.OnSuccess();
                    }
                    break;

                case CertAction.Bootstrap:
                    success = await BootstrapCertAsync(settings);
                    if (success)
                        _lifecycle.OnSuccess();
                    else
                        _lifecycle.OnFailure(false);
                    break;

                case CertAction.Wait:
                default:
                    break;
            }

            if (success)
                _logger.LogInformation("CertManagerService: cert rotated successfully (state={State})",
                    _lifecycle.State);
        }
    }

    private static bool IsCertPemExpired(string certPem)
    {
        if (string.IsNullOrWhiteSpace(certPem))
            return true;
        try
        {
            using var cert = new X509Certificate2(System.Text.Encoding.UTF8.GetBytes(certPem));
            return DateTime.UtcNow >= cert.NotAfter;
        }
        catch
        {
            return true;
        }
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

    private async Task RefreshCrlAsync()
    {
        var settings = _settingsService.Load();
        await FetchCrlAsync(settings);
    }

    public void Dispose()
    {
        _certCts?.Dispose();
        _crlTimer?.Dispose();
    }

}
