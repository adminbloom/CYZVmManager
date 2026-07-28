using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using VmManager.Agent.Services;
using VmManager.Contracts.Models;

namespace VmManager.Agent.Auth;

/// <summary>
/// Authenticates API callers via Keycloak Bearer JWTs (alongside Basic auth).
/// </summary>
public sealed class OidcAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly OidcTokenValidator? _validator;

    public OidcAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IServiceProvider services
    )
        : base(options, logger, encoder)
    {
        _validator = services.GetService<OidcTokenValidator>();
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (_validator == null)
            return Task.FromResult(AuthenticateResult.NoResult());

        string? authHeader = Request.Headers.Authorization.FirstOrDefault();
        if (
            authHeader == null
            || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        )
            return Task.FromResult(AuthenticateResult.NoResult());

        AuthenticatedUser? user = _validator.ValidateBearerToken(authHeader);
        if (user == null)
            return Task.FromResult(AuthenticateResult.Fail("Invalid or expired OIDC token"));

        List<Claim> claims =
        [
            new Claim(ClaimTypes.Name, string.IsNullOrEmpty(user.Username) ? user.Email : user.Username),
        ];

        if (!string.IsNullOrEmpty(user.Email))
            claims.Add(new Claim(ClaimTypes.Email, user.Email));

        if (user.IsAdmin)
        {
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            foreach (string permission in Permission.All)
                claims.Add(new Claim(Permission.PermissionClaimType, permission));
        }
        else
        {
            foreach (string permission in user.Permissions)
                claims.Add(new Claim(Permission.PermissionClaimType, permission));
        }

        ClaimsIdentity identity = new(claims, Scheme.Name);
        ClaimsPrincipal principal = new(identity);
        AuthenticationTicket ticket = new(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        Response.Headers.WWWAuthenticate = "Bearer realm=\"VmManager\"";
        return Task.CompletedTask;
    }
}
