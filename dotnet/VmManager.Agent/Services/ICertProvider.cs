using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VmManager.Agent.Services;

public interface ICertProvider
{
    Task<SignCsrResult> SignCsrAsync(string csrPem, List<string>? sanIps = null, List<string>? sanDns = null);
    Task<GetCertResult> GetCertAsync(string commonName);
    Task<RenewCertResult> RenewCertAsync(string certPem, string keyPem);
    Task<string?> FetchCrlAsync();
    Task<string?> FetchCaCertAsync();
}

public class RenewCertResult
{
    public string CertPem { get; set; } = "";
    public string Expiry { get; set; } = "";
    public bool Valid => !string.IsNullOrEmpty(CertPem);
}

public class SignCsrResult
{
    public string CertPem { get; set; } = "";
    public string Expiry { get; set; } = "";
    public bool Valid => !string.IsNullOrEmpty(CertPem);
}

public class GetCertResult
{
    public string CertPem { get; set; } = "";
    public string KeyPem { get; set; } = "";
    public string Expiry { get; set; } = "";
    public bool Valid => !string.IsNullOrEmpty(CertPem) && !string.IsNullOrEmpty(KeyPem);
}

public class FastApiCertProvider : ICertProvider
{
    private readonly string _baseUrl;
    private readonly string _authToken;
    private readonly string _caCertPath;
    private readonly string _crlUrl;
    private readonly ILogger _logger;

    public FastApiCertProvider(string certServerUrl, string authToken, string caCertPath, string crlUrl, ILogger logger)
    {
        _baseUrl = CertProviderFactory.StripUrlPath(certServerUrl);
        _authToken = authToken;
        _caCertPath = caCertPath;
        _crlUrl = string.IsNullOrEmpty(crlUrl) ? $"{_baseUrl}/crl.pem" : crlUrl;
        _logger = logger;
    }

    public async Task<SignCsrResult> SignCsrAsync(string csrPem, List<string>? sanIps = null, List<string>? sanDns = null)
    {
        var payload = new Dictionary<string, object> { ["csr_pem"] = csrPem };
        if (sanIps != null && sanIps.Count > 0)
            payload["san_ips"] = sanIps;
        if (sanDns != null && sanDns.Count > 0)
            payload["san_dns"] = sanDns;

        using var handler = CreateHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _authToken);

        var content = new StringContent(
            System.Text.Json.JsonSerializer.Serialize(payload),
            System.Text.Encoding.UTF8,
            "application/json"
        );

        HttpResponseMessage resp = await client.PostAsync($"{_baseUrl}/sign-csr", content);
        if (resp.IsSuccessStatusCode)
        {
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            return new SignCsrResult
            {
                CertPem = doc.RootElement.GetProperty("cert_pem").GetString() ?? "",
                Expiry = doc.RootElement.TryGetProperty("expiry", out var exp) ? exp.GetString() ?? "" : ""
            };
        }

        _logger.LogError("FastApiCertProvider: sign_csr failed: HTTP {Status}", resp.StatusCode);
        return new SignCsrResult();
    }

    public async Task<GetCertResult> GetCertAsync(string commonName)
    {
        using var handler = CreateHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _authToken);

        var content = new StringContent(
            System.Text.Json.JsonSerializer.Serialize(new { cn = commonName }),
            System.Text.Encoding.UTF8, "application/json");
        HttpResponseMessage resp = await client.PostAsync($"{_baseUrl}/issue-cert", content);

        if (resp.IsSuccessStatusCode)
        {
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            return new GetCertResult
            {
                CertPem = doc.RootElement.GetProperty("cert_pem").GetString() ?? "",
                KeyPem = doc.RootElement.GetProperty("key_pem").GetString() ?? "",
                Expiry = doc.RootElement.TryGetProperty("expiry", out var exp) ? exp.GetString() ?? "" : ""
            };
        }

        _logger.LogError("FastApiCertProvider: get_cert failed: HTTP {Status}", resp.StatusCode);
        return new GetCertResult();
    }

    public Task<RenewCertResult> RenewCertAsync(string certPem, string keyPem)
    {
        throw new NotImplementedException("FastAPI cert server does not support mTLS renewal");
    }

    public async Task<string?> FetchCrlAsync()
    {
        try
        {
            using var handler = CreateHandler();
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            HttpResponseMessage resp = await client.GetAsync(_crlUrl);
            if (resp.IsSuccessStatusCode)
                return await resp.Content.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            _logger.LogWarning("FastApiCertProvider: fetch_crl failed: {Error}", e.Message);
        }
        return null;
    }

    public async Task<string?> FetchCaCertAsync()
    {
        try
        {
            using var handler = CreateHandler();
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            HttpResponseMessage resp = await client.GetAsync($"{_baseUrl}/ca.crt");
            if (resp.IsSuccessStatusCode)
                return await resp.Content.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            _logger.LogWarning("FastApiCertProvider: fetch_ca_cert failed: {Error}", e.Message);
        }
        return null;
    }

    private HttpClientHandler CreateHandler()
    {
        var handler = new HttpClientHandler();
        if (File.Exists(_caCertPath))
            handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) =>
            {
                if (errors == System.Net.Security.SslPolicyErrors.None)
                    return true;
                try
                {
                    using var caCert = new X509Certificate2(_caCertPath);
                    chain!.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(caCert);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    return chain.Build(cert!);
                }
                catch
                {
                    return false;
                }
            };
        else
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        return handler;
    }
}

public class StepCaCertProvider : ICertProvider
{
    private readonly string _baseUrl;
    private readonly string _authToken;
    private readonly string _caCertPath;
    private readonly string _crlUrl;
    private readonly string _tokenCommand;
    private readonly ILogger _logger;

    public StepCaCertProvider(string certServerUrl, string authToken, string caCertPath,
        string crlUrl, string tokenCommand, ILogger logger)
    {
        _baseUrl = CertProviderFactory.StripUrlPath(certServerUrl);
        _authToken = authToken;
        _caCertPath = caCertPath;
        // Official step-ca CRL path is /1.0/crl (also on insecureAddress over HTTP).
        _crlUrl = string.IsNullOrEmpty(crlUrl) ? $"{_baseUrl}/1.0/crl" : crlUrl;
        _tokenCommand = tokenCommand ?? "";
        _logger = logger;
    }

    /// <summary>
    /// Bootstrap phase: POST /sign with a one-time token (OTT).
    /// The OTT is obtained by running the configured token command (e.g. 'step ca token').
    /// step-ca expects the JWT as 'ott' in the JSON body, not in the Authorization header.
    /// </summary>
    public async Task<SignCsrResult> SignCsrAsync(string csrPem, List<string>? sanIps = null, List<string>? sanDns = null)
    {
        try
        {
            string ott = await GetFreshTokenAsync(sanIps, sanDns);

            var payload = new Dictionary<string, object> { ["csr"] = csrPem, ["ott"] = ott };

            using var handler = CreateHandler();
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

            var content = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(payload),
                System.Text.Encoding.UTF8, "application/json");

            HttpResponseMessage resp = await client.PostAsync($"{_baseUrl}/sign", content);
            if (resp.IsSuccessStatusCode)
            {
                string body = await resp.Content.ReadAsStringAsync();
                string certPem = ExtractCertPem(body);
                if (string.IsNullOrEmpty(certPem))
                {
                    _logger.LogError("StepCaCertProvider: /sign response did not contain a certificate");
                    return new SignCsrResult();
                }
                string expiry = ExtractExpiry(certPem);
                return new SignCsrResult { CertPem = certPem, Expiry = expiry };
            }

            string errBody = await resp.Content.ReadAsStringAsync();
            _logger.LogError("StepCaCertProvider: /sign failed: HTTP {Status} {Body}",
                resp.StatusCode, errBody.Length > 200 ? errBody[..200] : errBody);
        }
        catch (Exception e)
        {
            _logger.LogError("StepCaCertProvider: /sign exception: {Error}", e.Message);
        }
        return new SignCsrResult();
    }

    /// <summary>
    /// Renewal phase: POST /renew using mTLS client certificate authentication.
    /// No token is needed - the existing client cert authenticates the request.
    /// Returns a renewed certificate for the same subject and SANs.
    /// </summary>
    public async Task<RenewCertResult> RenewCertAsync(string certPem, string keyPem)
    {
        string? certFile = null;
        string? keyFile = null;
        try
        {
            using var handler = CreateMtlsHandler(certPem, keyPem, out certFile, out keyFile);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

            var content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
            HttpResponseMessage resp = await client.PostAsync($"{_baseUrl}/renew", content);

            if (resp.IsSuccessStatusCode)
            {
                string body = await resp.Content.ReadAsStringAsync();
                string renewedCertPem = ExtractCertPem(body);
                if (string.IsNullOrEmpty(renewedCertPem))
                {
                    _logger.LogError("StepCaCertProvider: /renew response did not contain a certificate");
                    return new RenewCertResult();
                }
                string expiry = ExtractExpiry(renewedCertPem);
                _logger.LogInformation("StepCaCertProvider: cert renewed via mTLS /renew, expiry={Expiry}", expiry);
                return new RenewCertResult { CertPem = renewedCertPem, Expiry = expiry };
            }

            _logger.LogWarning("StepCaCertProvider: /renew failed: HTTP {Status}", resp.StatusCode);
        }
        catch (Exception e)
        {
            _logger.LogWarning("StepCaCertProvider: /renew exception: {Error}", e.Message);
        }
        finally
        {
            if (certFile != null)
            {
                try { File.Delete(certFile); } catch { }
            }
            if (keyFile != null)
            {
                try { File.Delete(keyFile); } catch { }
            }
        }
        return new RenewCertResult();
    }

    /// <summary>
    /// Generate a keypair + CSR locally, then sign via /sign (bootstrap phase).
    /// The private key never leaves the caller.
    /// </summary>
    public async Task<GetCertResult> GetCertAsync(string commonName)
    {
        var sanIps = CertProviderFactory.GetAgentLanIps();
        var sanDns = new List<string> { commonName };
        var (csrPem, keyPem) = CertProviderFactory.GenerateCsr(commonName, sanIps: sanIps, sanDns: sanDns);
        var result = await SignCsrAsync(csrPem, sanIps: sanIps, sanDns: sanDns);
        if (result.Valid)
        {
            return new GetCertResult { CertPem = result.CertPem, KeyPem = keyPem, Expiry = result.Expiry };
        }
        return new GetCertResult();
    }

    /// <summary>
    /// Fetch CRL from step-ca (/1.0/crl). Tries configured URL then common aliases.
    /// </summary>
    public async Task<string?> FetchCrlAsync()
    {
        var urls = new List<string> { _crlUrl };
        foreach (var alt in new[] { $"{_baseUrl}/1.0/crl", $"{_baseUrl}/crl" })
        {
            if (!urls.Contains(alt))
                urls.Add(alt);
        }

        using var handler = CreateHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        foreach (string url in urls)
        {
            try
            {
                HttpResponseMessage resp = await client.GetAsync(url);
                if (resp.IsSuccessStatusCode)
                {
                    byte[] raw = await resp.Content.ReadAsByteArrayAsync();
                    return NormalizeCrlToPem(raw);
                }
                if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                    continue;
                _logger.LogWarning("StepCaCertProvider: fetch_crl failed: HTTP {Status} from {Url}",
                    resp.StatusCode, url);
            }
            catch (Exception e)
            {
                _logger.LogWarning("StepCaCertProvider: fetch_crl exception for {Url}: {Error}",
                    url, e.Message);
            }
        }
        _logger.LogInformation("StepCaCertProvider: CRL endpoint not available");
        return null;
    }

    /// <summary>
    /// Fetch CA trust bundle: roots.pem + intermediates.pem (leafs are signed by intermediate).
    /// Falls back to local file at _caCertPath.
    /// </summary>
    public async Task<string?> FetchCaCertAsync()
    {
        // Always prefer a fresh roots+intermediates bundle from step-ca.
        // A stale root-only file on disk must not short-circuit the download
        // (portal client certs are intermediate-signed → unknown_ca otherwise).
        try
        {
            using var handler = CreateHandler();
            // When no CA file exists yet, CreateHandler already skips verification.
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            HttpResponseMessage rootsResp = await client.GetAsync($"{_baseUrl}/roots.pem");
            HttpResponseMessage intResp = await client.GetAsync($"{_baseUrl}/intermediates.pem");
            if (rootsResp.IsSuccessStatusCode && intResp.IsSuccessStatusCode)
            {
                string roots = await rootsResp.Content.ReadAsStringAsync();
                string intermediates = await intResp.Content.ReadAsStringAsync();
                string bundle = (roots.TrimEnd() + "\n" + intermediates.TrimEnd() + "\n");
                if (bundle.Contains("BEGIN CERTIFICATE")
                    && bundle.Split("BEGIN CERTIFICATE", StringSplitOptions.None).Length > 2)
                    return bundle;
            }
            if (rootsResp.IsSuccessStatusCode)
            {
                string pem = await rootsResp.Content.ReadAsStringAsync();
                if (pem.Contains("BEGIN CERTIFICATE"))
                    return pem;
            }
            _logger.LogWarning("StepCaCertProvider: fetch_ca_cert failed: roots={R} intermediates={I}",
                rootsResp.StatusCode, intResp.StatusCode);
        }
        catch (Exception e)
        {
            _logger.LogWarning("StepCaCertProvider: fetch_ca_cert exception: {Error}", e.Message);
        }

        if (File.Exists(_caCertPath))
        {
            try
            {
                string existing = File.ReadAllText(_caCertPath);
                if (existing.Contains("BEGIN CERTIFICATE"))
                    return existing;
            }
            catch { /* ignore */ }
        }
        return null;
    }

    /// <summary>
    /// Run the configured token command to obtain a fresh JWT (one-time token).
    /// Appends --san for each DNS/IP so CSR SANs match the OTT (step-ca requirement).
    /// Falls back to _authToken if no command is configured.
    /// </summary>
    private async Task<string> GetFreshTokenAsync(List<string>? sanIps = null, List<string>? sanDns = null)
    {
        if (!string.IsNullOrEmpty(_tokenCommand))
        {
            var cmd = _tokenCommand;
            var extras = new List<string>();
            if (sanDns != null)
            {
                foreach (var dns in sanDns)
                {
                    if (!string.IsNullOrWhiteSpace(dns))
                        extras.Add($"--san \"{dns.Replace("\"", "")}\"");
                }
            }
            if (sanIps != null)
            {
                foreach (var ip in sanIps)
                {
                    if (!string.IsNullOrWhiteSpace(ip))
                        extras.Add($"--san \"{ip.Replace("\"", "")}\"");
                }
            }
            if (extras.Count > 0)
                cmd = $"{cmd} {string.Join(" ", extras)}";

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {cmd}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var stdoutTask = proc.StandardOutput.ReadToEndAsync();
                var stderrTask = proc.StandardError.ReadToEndAsync();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                try
                {
                    await proc.WaitForExitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
                    _logger.LogWarning("StepCaCertProvider: token command timed out");
                    return _authToken;
                }
                string output = await stdoutTask;
                string err = await stderrTask;
                if (proc.ExitCode != 0)
                    _logger.LogWarning("StepCaCertProvider: token command rc={Code} stderr={Err}",
                        proc.ExitCode, err.Length > 300 ? err[..300] : err);
                string trimmed = output.Trim();
                foreach (var line in trimmed.Split('\n'))
                {
                    var l = line.Trim();
                    if (l.StartsWith("eyJ"))
                        return l;
                }
                if (trimmed.StartsWith("eyJ"))
                    return trimmed;
                return string.IsNullOrEmpty(trimmed) ? _authToken : trimmed;
            }
        }
        _logger.LogWarning("StepCaCertProvider: no token command configured, using static auth_token as OTT (security risk)");
        return _authToken;
    }

    private static string NormalizeCrlToPem(byte[] raw)
    {
        if (raw == null || raw.Length == 0)
            return "";
        string asText = System.Text.Encoding.ASCII.GetString(raw);
        if (asText.Contains("-----BEGIN", StringComparison.Ordinal))
            return asText;
        string b64 = Convert.ToBase64String(raw, Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN X509 CRL-----\n" + b64 + "\n-----END X509 CRL-----\n";
    }

    private static string ExtractCertPem(string body)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("crt", out var crt))
                return crt.GetString() ?? "";
            if (doc.RootElement.TryGetProperty("cert", out var cert))
                return cert.GetString() ?? "";
            if (doc.RootElement.TryGetProperty("cert_pem", out var cp))
                return cp.GetString() ?? "";
        }
        catch { }
        if (body.Contains("BEGIN CERTIFICATE"))
            return body;
        return "";
    }

    private static string ExtractExpiry(string certPem)
    {
        try
        {
            using var cert = new X509Certificate2(System.Text.Encoding.ASCII.GetBytes(certPem));
            return cert.NotAfter.ToString("o");
        }
        catch { return ""; }
    }

    private HttpClientHandler CreateHandler()
    {
        var handler = new HttpClientHandler();
        if (File.Exists(_caCertPath))
            handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) =>
            {
                if (errors == System.Net.Security.SslPolicyErrors.None)
                    return true;
                try
                {
                    chain!.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    // Roots → CustomTrustStore; intermediates → ExtraStore (required for
                    // intermediate-signed step-ca / portal leaves).
                    foreach (var ca in LoadPemCerts(_caCertPath))
                    {
                        if (ca.Subject == ca.Issuer)
                            chain.ChainPolicy.CustomTrustStore.Add(ca);
                        else
                            chain.ChainPolicy.ExtraStore.Add(ca);
                    }
                    // Online CRL checks hang/fail on LAN step-ca IDP URLs during bootstrap.
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    return chain.Build(cert!);
                }
                catch { return false; }
            };
        else
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        return handler;
    }

    private static List<X509Certificate2> LoadPemCerts(string path)
    {
        var list = new List<X509Certificate2>();
        string pem = File.ReadAllText(path);
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        int idx = 0;
        while (true)
        {
            int start = pem.IndexOf(begin, idx, StringComparison.Ordinal);
            if (start < 0) break;
            int stop = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0) break;
            stop += end.Length;
            list.Add(X509Certificate2.CreateFromPem(pem.AsSpan(start, stop - start)));
            idx = stop;
        }
        if (list.Count == 0)
            list.Add(X509CertificateLoader.LoadCertificateFromFile(path));
        return list;
    }

    /// <summary>
    /// Create an HttpClientHandler configured for mTLS client certificate authentication.
    /// Used for the /renew endpoint which authenticates via the existing client cert.
    /// </summary>
    private HttpClientHandler CreateMtlsHandler(string certPem, string keyPem,
        out string certFilePath, out string keyFilePath)
    {
        var handler = CreateHandler();

        var tempDir = Path.Combine(Path.GetTempPath(), "bloomce_certs");
        Directory.CreateDirectory(tempDir);
        certFilePath = Path.Combine(tempDir, "stepca_renew_cert.pem");
        keyFilePath = Path.Combine(tempDir, "stepca_renew_key.pem");
        File.WriteAllText(certFilePath, certPem);
        File.WriteAllText(keyFilePath, keyPem);

        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        // CreateFromPemFile alone yields an ephemeral key that Schannel often cannot
        // use as a client cert on Windows (SSL connection fails on /renew).
        using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certFilePath, keyFilePath);
        byte[] pfx = pem.Export(X509ContentType.Pkcs12);
        handler.ClientCertificates.Add(
            X509CertificateLoader.LoadPkcs12(
                pfx,
                password: null,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable
            )
        );

        return handler;
    }
}

public static class CertProviderFactory
{
    public static string StripUrlPath(string url)
    {
        var trimmed = url.TrimEnd('/');
        var schemePos = trimmed.IndexOf("://");
        if (schemePos < 0) return trimmed;
        var hostStart = schemePos + 3;
        var pathPos = trimmed.IndexOf('/', hostStart);
        return pathPos >= 0 ? trimmed[..pathPos] : trimmed;
    }

    public static ICertProvider Create(string providerName, string certServerUrl,
        string authToken, string caCertPath, string crlUrl, ILogger logger,
        string stepCaTokenCommand = "")
    {
        var name = providerName.ToLower().Trim();
        if (name == "fastapi")
            return new FastApiCertProvider(certServerUrl, authToken, caCertPath, crlUrl, logger);
        if (name == "step-ca")
            return new StepCaCertProvider(certServerUrl, authToken, caCertPath, crlUrl,
                stepCaTokenCommand, logger);
        throw new ArgumentException($"Unknown cert provider: {providerName}");
    }

    public static (string csrPem, string keyPem) GenerateCsr(string commonName, List<string>? sanIps = null, List<string>? sanDns = null)
    {
        using var ecd = ECDsa.Create(ECCurve.CreateFromValue("1.2.840.10045.3.1.7")); // P-256
        var req = new CertificateRequest(
            $"CN={commonName}", ecd, HashAlgorithmName.SHA256);

        if (sanIps != null || sanDns != null)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            if (sanDns != null)
                foreach (var dns in sanDns)
                    sanBuilder.AddDnsName(dns);
            if (sanIps != null)
                foreach (var ip in sanIps)
                    if (System.Net.IPAddress.TryParse(ip, out var addr))
                        sanBuilder.AddIpAddress(addr);
            req.CertificateExtensions.Add(sanBuilder.Build());
        }

        string csrPem = req.CreateSigningRequestPem();
        string keyPem = ecd.ExportPkcs8PrivateKeyPem();
        return (csrPem, keyPem);
    }

    public static List<string> GetAgentLanIps()
    {
        var ips = new List<string>();
        try
        {
            var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
            foreach (var addr in host.AddressList)
            {
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    string ipStr = addr.ToString();
                    if (!ipStr.StartsWith("127.") && !ipStr.StartsWith("169.254."))
                        ips.Add(ipStr);
                }
            }
        }
        catch { }
        return ips;
    }
}
