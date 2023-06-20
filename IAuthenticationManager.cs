namespace Lru.Stil.Oidc;

public interface IAuthenticationManager
{
    public Task<bool> ValidatePathAsync(string clientId, string path, string auth);
    public Task<string?> CreateAuthStringAsync(string clientId, string timestamp, string userName);

    public string GetClientPath(string path);

    public Task<string?> GetClientAuthAsync(string path, string clientId);
}