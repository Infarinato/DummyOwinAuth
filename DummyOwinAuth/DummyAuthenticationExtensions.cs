namespace DummyOwinAuth
{
    using Owin;

    public static class DummyAuthenticationExtensions
    {
        public static IAppBuilder UseDummyAuthentication(this IAppBuilder app, DummyAuthenticationOptions options)
        {
            return app.Use(typeof(DummyAuthenticationMiddleware), app, options);
        }
    }
}