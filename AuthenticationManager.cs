using Microsoft.Extensions.Options;
using Lru.Stil.Oidc.Models;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Lru.Stil.Oidc;

public class AuthenticationManager : IAuthenticationManager
{
    // TODO: Is this thread safe?
    private static readonly MD5 md5 = MD5.Create();
    private readonly List<SSOProxyClient> Clients;

    public AuthenticationManager(IOptions<List<SSOProxyClient>> ssoProxyClients)
    {
        Clients = ssoProxyClients.Value;
    }

    public async Task<bool> ValidatePathAsync(string clientId, string path, string auth)
    {
        var secret = GetSecret(clientId);
        if (secret is null) return false;

        var pathAsBytes = Convert.FromBase64String(path);
        var decodedPath = Encoding.ASCII.GetString(pathAsBytes);

        var fingerPrint = await FingerPrintAsync(decodedPath + secret);

        return fingerPrint?.ToLower() == auth.ToLower();
    }

    public string GetClientPath(string path)
    {
        // path = URI_ESCAPE(BASE64(path))
        var base64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(path));
        return WebUtility.UrlEncode(base64);
    }

    public async Task<string?> GetClientAuthAsync(string path, string clientId)
    {
        var secret = GetSecret(clientId);

        return secret is null ? null : await FingerPrintAsync(path + secret);
    }

    public async Task<string?> CreateAuthStringAsync(string clientId, string timestamp, string userName)
    {
        var secret = GetSecret(clientId);

        return secret is null ? null : await FingerPrintAsync(timestamp + secret + userName);
    }

    private async Task<string?> FingerPrintAsync(string input)
    {
        var fingerprintAsBytes = Encoding.ASCII.GetBytes(input);

        var stream = new MemoryStream(fingerprintAsBytes);

        var fingerprint = Convert.ToHexString(await md5.ComputeHashAsync(stream));

        return fingerprint;
    }

    private string? GetSecret(string clientId) 
        => Clients.FirstOrDefault(client => client.ClientId == clientId)?.Secret;
}