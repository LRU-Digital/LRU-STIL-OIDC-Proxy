using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Lru.Stil.Oidc;
using Microsoft.AspNetCore.Authentication;
using Lru.Stil.Oidc.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});

builder.Services.AddAuthentication(options => {
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options => {
    options.ClientId = builder.Configuration["STILOIDC:ClientId"]; 
    options.ClientSecret = builder.Configuration["STILOIDC:ClientSecret"]; 
    options.Authority = $"https://{builder.Configuration["STILOIDC:Domain"]}/"; 
    options.ResponseType = "code";
 
    options.MapInboundClaims = false;
    // The next two settings must match the Callback URLs
    options.CallbackPath = new PathString("/callback"); 
    options.SignedOutCallbackPath = new PathString("/signout");
    options.UsePkce = builder.Configuration.GetValue<bool>("STILOIDC:UsePkce");
    options.Events = new OpenIdConnectEvents() 
    {
        // TODO: Ok - so its a bit tricky. OIDC does not seem to have standardized signout and the asp.net implementation
        // will try to fetch the OIDC metadata from {options.Authority}/.well-known/openid-configuration 
        // (in Googles case: https://accounts.google.com/.well-known/openid-configuration) 
        // If the metadata does not have "end_session_endpoint" the framework will fail.
        // The following adds the google logout url to manage logout from OIDC
        OnRedirectToIdentityProviderForSignOut = context =>
        {
            context.ProtocolMessage.IssuerAddress = "https://www.google.com/accounts/Logout";
            return Task.CompletedTask;
        },

        OnTokenResponseReceived = context =>
        {
            var logger = GetLogger(context);
            logger.LogTrace("Token response received. Accesstoken length: {length}", context.TokenEndpointResponse.AccessToken.Length);

            return Task.CompletedTask;
        },

        OnAuthenticationFailed = context =>
        {
            var logger = GetLogger(context);
            logger.LogError(context.Exception, "Authentication failed with result {result}", context.Result);

            return Task.CompletedTask;
        }
    };
});
 
builder.Services.AddScoped<IAuthenticationManager, AuthenticationManager>();
builder.Services.Configure<List<SSOProxyClient>>(builder.Configuration.GetSection("SSOProxyClients"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// After hours of debugging I found out that the order of the following two matters
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static ILogger GetLogger(RemoteAuthenticationContext<OpenIdConnectOptions> context)
{
    var loggerFactory = context.HttpContext.RequestServices.GetService<ILoggerFactory>();
    var logger = loggerFactory.CreateLogger(nameof(Program));
    return logger;
}