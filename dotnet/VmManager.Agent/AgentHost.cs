using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using MudBlazor.Services;
using Serilog;
using VmManager.Agent.Auth;
using VmManager.Agent.Components;
using VmManager.Agent.Components.Auth;
using VmManager.Agent.Endpoints;
using VmManager.Agent.Hubs;
using VmManager.Agent.Services;
using VmManager.Agent.Services.Rdp;

namespace VmManager.Agent;

public static class AgentHost
{
    public static async Task RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        Log.Information("AgentHost.RunAsync starting");

        RdpCredSspConnectionHandler? rdpHandler = null;

        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        builder.Host.UseSerilog();
        builder.WebHost.UseStaticWebAssets();

        int httpPort = builder.Configuration.GetValue("VmManager:HttpPort", 18275);

        bool enableTls = builder.Configuration.GetValue("VmManager:EnableTls", false);
        bool requireClientCert = builder.Configuration.GetValue("VmManager:RequireClientCert", false);
        string? certServerUrl = builder.Configuration.GetValue<string>("VmManager:CertServerUrl");

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            if (enableTls && !string.IsNullOrEmpty(certServerUrl))
            {
                string defaultCertDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "BloomCE", "certs"
                );
                string serverCertPath = builder.Configuration.GetValue("VmManager:ServerCertPath",
                    Path.Combine(defaultCertDir, "agent_server_cert.pem"));
                string serverKeyPath = builder.Configuration.GetValue("VmManager:ServerKeyPath",
                    Path.Combine(defaultCertDir, "agent_server_key.pem"));
                string caCertPath = builder.Configuration.GetValue("VmManager:CaCertPath",
                    Path.Combine(defaultCertDir, "ca_cert.pem"));

                {
                    kestrel.ListenAnyIP(
                        httpPort,
                        listenOptions =>
                        {
                            // Deferred cert loading: read cert at connection time so it works
                            // even if CertManagerService fetches it after Kestrel starts.
                            listenOptions.UseHttps(options =>
                            {
                                options.ServerCertificateSelector = (_, _) =>
                                {
                                    if (File.Exists(serverCertPath) && File.Exists(serverKeyPath))
                                    {
                                        return X509Certificate2.CreateFromPemFile(serverCertPath, serverKeyPath);
                                    }
                                    Log.Warning("AgentHost: server cert not yet available at {CertPath}", serverCertPath);
                                    return null;
                                };
                            });
                            if (requireClientCert)
                            {
                                string expectedCn = builder.Configuration.GetValue("VmManager:ExpectedClientCN", "bloomce-client");
                                ((Microsoft.AspNetCore.Builder.IApplicationBuilder)listenOptions).Use(next =>
                                    {
                                        return async context =>
                                        {
                                            var clientCert = await context.Connection.GetClientCertificateAsync();
                                            if (clientCert == null)
                                            {
                                                context.Response.StatusCode = 403;
                                                return;
                                            }
                                            if (!File.Exists(caCertPath))
                                            {
                                                context.Response.StatusCode = 503;
                                                return;
                                            }
                                            using var caCert = new X509Certificate2(caCertPath);
                                            using var chain = new X509Chain();
                                            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                                            chain.ChainPolicy.CustomTrustStore.Add(caCert);
                                            string crlPath = builder.Configuration.GetValue("VmManager:CrlPath",
                                                Path.Combine(defaultCertDir, "crl.pem"));
                                            if (File.Exists(crlPath))
                                            {
                                                chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
                                            }
                                            else
                                            {
                                                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                                            }
                                            if (!chain.Build(clientCert))
                                            {
                                                context.Response.StatusCode = 403;
                                                return;
                                            }
                                            // Validate CN matches expected client CN
                                            string certCn = clientCert.GetNameInfo(X509NameType.SimpleName, false) ?? "";
                                            if (!string.IsNullOrEmpty(expectedCn) &&
                                                !certCn.Equals(expectedCn, StringComparison.OrdinalIgnoreCase))
                                            {
                                                Log.Warning("AgentHost: client cert CN mismatch: expected={Expected}, got={Actual}", expectedCn, certCn);
                                                context.Response.StatusCode = 403;
                                                return;
                                            }
                                            await next(context);
                                        };
                                    });
                            }
                            listenOptions.Use(next =>
                                async context =>
                                {
                                    System.IO.Pipelines.PipeReader input = context.Transport.Input;
                                    System.IO.Pipelines.ReadResult result = await input.ReadAsync(
                                        context.ConnectionClosed
                                    );
                                    System.Buffers.ReadOnlySequence<byte> buffer = result.Buffer;

                                    if (buffer.Length > 0 && buffer.First.Span[0] == 0x03)
                                    {
                                        input.AdvanceTo(buffer.Start);
                                        DuplexPipeStream stream = new DuplexPipeStream(
                                            input,
                                            context.Transport.Output
                                        );
                                        await rdpHandler!.HandleConnectionAsync(
                                            stream,
                                            context.ConnectionClosed
                                        );
                                        return;
                                    }

                                    input.AdvanceTo(buffer.Start);
                                    await next(context);
                                }
                            );
                        }
                    );
                    Log.Information("AgentHost: HTTPS enabled on port {Port} with client cert validation={RequireClient}, expectedCN={ExpectedCn}",
                        httpPort, requireClientCert, builder.Configuration.GetValue("VmManager:ExpectedClientCN", "bloomce-client"));
                }
            }
            else
            {
                ConfigureHttpListener(kestrel, httpPort, rdpHandler);
            }
        });

        Log.Information("AgentHost: configuring services");

        if (OperatingSystem.IsWindows())
            builder.Services.AddWindowsService();
        else if (OperatingSystem.IsLinux())
            builder.Host.UseSystemd();
        string? vmBackend = ReadVmBackendFromSettings();
        builder.Services.AddBackendServices(vmBackend);
        builder.Services.AddCatalogServices();
        builder.Services.AddAgentServices(vmBackend);

        builder
            .Services.AddAuthentication("Basic")
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("Basic", null);

        builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        builder.Services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder("Basic")
                .RequireAuthenticatedUser()
                .Build();

            foreach (string permission in Permission.All)
            {
                options.AddPolicy(
                    permission,
                    policy => policy.AddRequirements(new PermissionRequirement(permission))
                );
            }
        });

        builder.Services.AddControllers().AddApplicationPart(typeof(AgentHost).Assembly);
        builder.Services.AddSignalR();
        builder.Services.AddHealthChecks();
        builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        builder.Services.AddMudServices();
        builder.Services.AddScoped<BasicAuthStateProvider>();
        builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
            sp.GetRequiredService<BasicAuthStateProvider>()
        );
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            string xmlFile = Path.ChangeExtension(typeof(AgentHost).Assembly.Location, ".xml");
            if (File.Exists(xmlFile))
                options.IncludeXmlComments(xmlFile);
        });
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy
                    .SetIsOriginAllowed(_ => true)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });

        Log.Information("AgentHost: building app");
        WebApplication app = builder.Build();

        rdpHandler = app.Services.GetRequiredService<RdpCredSspConnectionHandler>();

        app.UseForwardedHeaders(
            new ForwardedHeadersOptions
            {
                ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            }
        );
        app.UseCors();
        app.UseAuthentication();
        app.UseMiddleware<Auth.MustChangePasswordMiddleware>();
        app.UseAuthorization();
        app.UseAntiforgery();
        try
        {
            app.MapStaticAssets();
        }
        catch
        {
            app.UseStaticFiles();
        }
        app.UseWhen(
            context => context.Request.Path.StartsWithSegments("/swagger"),
            branch =>
                branch.Use(
                    async (context, next) =>
                    {
                        if (!context.User.Identity?.IsAuthenticated ?? true)
                        {
                            context.Response.StatusCode = 401;
                            context.Response.Headers.Append(
                                "WWW-Authenticate",
                                "Basic realm=\"VmManager\""
                            );
                            return;
                        }
                        await next();
                    }
                )
        );
        app.UseSwagger();
        app.UseSwaggerUI();
        app.MapControllers();
        app.MapHub<ProgressHub>("/hubs/progress");
        app.MapHealthChecks("/health").AllowAnonymous();
        app.MapRdpEndpoints();
        app.MapPrometheusEndpoints();
        app.MapRazorComponents<App>().AddInteractiveServerRenderMode().AllowAnonymous();

        int rdpProxyPort = builder.Configuration.GetValue("VmManager:RdpProxyPort", 13389);
        if (rdpProxyPort > 0)
        {
            RdpProxyListener rdpProxyListener = app.Services.GetRequiredService<RdpProxyListener>();
            _ = Task.Run(
                async () =>
                {
                    try
                    {
                        await rdpProxyListener.StartAsync(rdpProxyPort, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "RDP proxy listener crashed");
                    }
                },
                cancellationToken
            );
        }

        Log.Information(
            "AgentHost: starting (HTTP+RDP :{HttpPort}{StandaloneRdp})",
            httpPort,
            rdpProxyPort > 0 ? ", standalone RDP :" + rdpProxyPort : ""
        );
        Task runTask = app.RunAsync();
        cancellationToken.Register(() => app.StopAsync().GetAwaiter().GetResult());
        await runTask;
    }

    private static void ConfigureHttpListener(Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions kestrel, int httpPort, RdpCredSspConnectionHandler? rdpHandler)
    {
        kestrel.ListenAnyIP(
            httpPort,
            listenOptions =>
            {
                listenOptions.Use(next =>
                    async context =>
                    {
                        System.IO.Pipelines.PipeReader input = context.Transport.Input;
                        System.IO.Pipelines.ReadResult result = await input.ReadAsync(
                            context.ConnectionClosed
                        );
                        System.Buffers.ReadOnlySequence<byte> buffer = result.Buffer;

                        if (buffer.Length > 0 && buffer.First.Span[0] == 0x03)
                        {
                            input.AdvanceTo(buffer.Start);
                            DuplexPipeStream stream = new DuplexPipeStream(
                                input,
                                context.Transport.Output
                            );
                            await rdpHandler!.HandleConnectionAsync(
                                stream,
                                context.ConnectionClosed
                            );
                            return;
                        }

                        input.AdvanceTo(buffer.Start);
                        await next(context);
                    }
                );
            }
        );
    }

    private static string? ReadVmBackendFromSettings()
    {
        string settingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "VmManager",
            "settings.json"
        );
        if (!File.Exists(settingsPath))
            return null;

        try
        {
            string json = File.ReadAllText(settingsPath);
            JsonDocument doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("VmBackend", out JsonElement val))
                return val.GetString();
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to read VmBackend from settings");
        }
        return null;
    }
}
