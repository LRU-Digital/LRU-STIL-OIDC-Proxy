using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;

namespace Lru.Stil.Oidc.Controllers;

public class AuthenticationController : Controller
{
    private readonly string SSO_PROXY_RETURN_URL_KEY = "ssoproxy.returnurl";

    private readonly string SSO_PROXY_CLIENT_ID_KEY = "ssoproxy.clientid";

    private readonly string SSO_PROXY_CORRELATION_ID_KEY = "ssoproxy.correlationid";

    private readonly ILogger _logger;

    private readonly IAuthenticationManager _authenticationManager;

    private readonly IConfiguration _configuration;

    public AuthenticationController(ILogger<AuthenticationController> logger, IAuthenticationManager authenticationManager, IConfiguration configuration)
    {
        _logger = logger;
        _authenticationManager = authenticationManager;
        _configuration = configuration;
    }

    public IActionResult Index()
    {
        return Content("This is fine - but not with GET!");
    }

    /*
    Responds to the same url as SSOProxy from STIL 
    https://viden.stil.dk/display/OFFSKOLELOGIN/SSOproxy+HTTP 

    https://localhost:7090/Authentication/Login?id=test&path=aHR0cDovL3d3dy5lbXUuZGsvYXBwbA%3D%3D&auth=59169cb39fab40cb0ad6ade6a6eb491e  
    */
    [HttpGet]
    public async Task<IActionResult> Login(string id, string path, string auth)
    {
        if (!await _authenticationManager.ValidatePathAsync(id, path, auth))
        {
            return BadRequest("Query parameters could not be validated");
        }

        var correlationId = Guid.NewGuid().ToString();
        var cookieOptions = new CookieOptions()
        {
            Path = "/",
            Secure = true,
            HttpOnly = true
        };

        Response.Cookies.Append(SSO_PROXY_RETURN_URL_KEY, path, cookieOptions);
        Response.Cookies.Append(SSO_PROXY_CLIENT_ID_KEY, id, cookieOptions);
        Response.Cookies.Append(SSO_PROXY_CORRELATION_ID_KEY, correlationId, cookieOptions);

        // Redirect to protected ressource to initiate OIDC login
        _logger.LogInformation("Correlation id: {0}. Redirecting to protected ressource", correlationId);
        return Redirect("/Authentication/Protected");
    }


    [Authorize()] // If not already authenticated, this kicks off the process
    public async Task<IActionResult> Protected()
    {
        var correlationId = Request.Cookies[SSO_PROXY_CORRELATION_ID_KEY] ?? "UNKNOWN";
        var content = new StringBuilder();

        content.AppendLine("Succesfully authenticated user:");

        var userNameClaimType = _configuration["STILOIDC:UserNameClaimType"] ?? throw new Exception("STILOIDC:UserNameClaimType is not configured");

        var userName = User.Claims.Where(claim => claim.Type == userNameClaimType).Select(claim => claim.Value).FirstOrDefault() ?? throw new Exception($"{userNameClaimType} is not present in claims");

        if (userName is null)
        {
            _logger.LogError("Could not get the user name. CorrelationId {0} | Cookies {1}", correlationId, Request.Cookies);
            return await LogoutAndBadRequest(correlationId);
        }

        var clientId = Request.Cookies[SSO_PROXY_CLIENT_ID_KEY];
        var returnUrl = Request.Cookies[SSO_PROXY_RETURN_URL_KEY];

        if (clientId is null || returnUrl is null)
        {
            _logger.LogError("Could not get the cookies from request. CorrelationId {0} | UserId {1} | ClientId {2} | ReturnUrl {3}", correlationId, userName, clientId, returnUrl);
            return await LogoutAndBadRequest(correlationId);
        }

        var url = await CreateUrlAsync(clientId, userName, returnUrl, correlationId);

        content.AppendLine();
        content.AppendLine($"Welcome back - {userName} - now you should return to the service provider with Url: {url}");
        content.AppendLine();

        var claims = User.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer));
        var claimsAsJson = JsonSerializer.Serialize(claims, options: new JsonSerializerOptions { WriteIndented = true });
        content.AppendLine(claimsAsJson);

        return Content(content.ToString());
    }

    private record Claim(string Type, string Value, string ValueType, string Issuer);

    private async Task<IActionResult> LogoutAndBadRequest(string? correlationId)
    {
        // Try logging out since something has gone wrong.
        await Logout();
        return BadRequest($"Error - CorrelationId: {correlationId}");
    }

    public async Task Logout()
    {
        // TODO: This will logout of the OIDC federation as well - commented out for now
        //await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ClearCookies();
    }

    private async Task<string?> CreateUrlAsync(string clientId, string userName, string returnUrl, string correlationId)
    {
        var timestamp = DateTime.Now.ToUniversalTime().ToString("yyyyMMddHHmmss");
        var auth = await _authenticationManager.CreateAuthStringAsync(clientId, timestamp, userName);

        if (auth is null) return null;

        // TODO: Reconsider logging username
        _logger.LogInformation("Logging in {0}", userName);
        LogCookies(correlationId);
        LogClaims(correlationId);

        // After return from OIDC - redirect back to the original client
        // Must redirect something like
        // https://{hostname}/{returnUrl}?user=testuser&timestamp=20030505125952&auth=5e55280df202c8820a7092746b991088
        var returnUrlDecoded = Encoding.ASCII.GetString(Base64UrlTextEncoder.Decode(returnUrl));

        var escapedUserName = Uri.EscapeDataString(userName);
        var queryPart = $"user={escapedUserName}&timestamp={timestamp}&auth={auth}";
        var url = $"{returnUrlDecoded}?{queryPart}";

        return url;
    }

    private void ClearCookies()
    {
        Response.Cookies.Delete(SSO_PROXY_CLIENT_ID_KEY);
        Response.Cookies.Delete(SSO_PROXY_CORRELATION_ID_KEY);
        Response.Cookies.Delete(SSO_PROXY_RETURN_URL_KEY);
    }

    private static string JoinKeyValueCollection(IEnumerable<KeyValuePair<string, string>> keyvalues, string joinCharacter = ":")
        => string.Join(joinCharacter, keyvalues.Select(x => new { x.Key, x.Value }));

    private static string JoinKeyValueCollection(IEnumerable<Claim> claims, string joinCharacter = ":")
        => string.Join(joinCharacter, claims.Select(x => new { x.Type, x.Value }));

    private void LogCookies(string? correlationId)
        => _logger.LogInformation($"CorrelationId: {correlationId}. Cookies : {JoinKeyValueCollection(Request.Cookies)}");

    private void LogClaims(string? correlationId)
    {
        var userClaims = User.Claims.Select(c => new KeyValuePair<string, string>(c.Type, c.Value));
        _logger.LogInformation($"CorrelationId: {correlationId}. Claims : {JoinKeyValueCollection(userClaims)}");
    }
}