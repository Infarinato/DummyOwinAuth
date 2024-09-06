namespace DummyOwinAuth
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    public class DummyAuthenticationOptions : AuthenticationOptions
    {
        public DummyAuthenticationOptions(string userName, string userId) : base(Constants.DefaultAuthenticationType)
        {
            this.Description.Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = new PathString("/signin-dummy");
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.UserName = userName;
            this.UserId = userId;
        }

        public PathString CallbackPath { get; set; }

        public string UserName { get; set; }

        public string UserId { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}