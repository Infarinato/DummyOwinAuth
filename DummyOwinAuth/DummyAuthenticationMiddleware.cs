namespace DummyOwinAuth
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using Owin;

    // One instance is created when the application starts
    public class DummyAuthenticationMiddleware : AuthenticationMiddleware<DummyAuthenticationOptions>
    {
        public DummyAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, DummyAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            if (options.StateDataFormat != null)
            {
                return;
            }

            var dataProtector = app.CreateDataProtector(typeof(DummyAuthenticationMiddleware).FullName, options.AuthenticationType);

            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }

        // Called for each request, to create a handler for each request
        protected override AuthenticationHandler<DummyAuthenticationOptions> CreateHandler()
        {
            return new DummyAuthenticationHandler();
        }
    }
}