namespace DummyOwinAuth
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    // Created by the factory in the DummyAuthenticationMiddleware class
    public class DummyAuthenticationHandler : AuthenticationHandler<DummyAuthenticationOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // ASP.NET Identity requires the NameIdentifier field to be set, or it won't  
            // accept the external login (AuthenticationManagerExtensions.GetExternalLoginInfo)
            var identity = new ClaimsIdentity(this.Options.SignInAsAuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, this.Options.UserId, null, this.Options.AuthenticationType));
            identity.AddClaim(new Claim(ClaimTypes.Name, this.Options.UserName));
            identity.AddClaim(new Claim("http://schemas.hants.gov.uk/2012/01/claims/x-customclaim", "Test"));
            var properties = this.Options.StateDataFormat.Unprotect(this.Request.Query["state"]);
            return Task.FromResult(new AuthenticationTicket(identity, properties));
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

            // Only react to 401 if there is an authentication challenge for the authentication type of this handler
            if (challenge == null)
            {
                return Task.FromResult<object>(null);
            }

            var state = challenge.Properties;
            if (string.IsNullOrEmpty(state.RedirectUri))
            {
                state.RedirectUri = this.Request.Uri.ToString();
            }

            var stateString = this.Options.StateDataFormat.Protect(state);
            this.Response.Redirect(WebUtilities.AddQueryString(this.Options.CallbackPath.Value, "state", stateString));
            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            // This is always invoked on each request. For passive middleware, only do anything if this is
            // for our callback path when the user is redirected back from the authentication provider
            if (!this.Options.CallbackPath.HasValue || this.Options.CallbackPath != this.Request.Path)
            {
                return false;
            }

            var ticket = await this.AuthenticateAsync();
            if (ticket == null)
            {
                return false;
            }

            this.Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
            this.Response.Redirect(ticket.Properties.RedirectUri);

            // Prevent further processing by the owin pipeline
            return true;

            // Let the rest of the pipeline run
        }
    }
}