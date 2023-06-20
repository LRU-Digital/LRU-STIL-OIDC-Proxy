using System.Diagnostics;
using Lru.Stil.Oidc.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace Lru.Stil.Oidc.Controllers;

public class HomeController : Controller
{
    private readonly IAuthenticationManager _authenticationManager;

    public HomeController(IAuthenticationManager authenticationManager)
    {
        _authenticationManager = authenticationManager;
    }

    public async Task<IActionResult> IndexAsync()
    {
        var clientId = "test";
        var path = "http://www.emu.dk/appl";
        var model = new HomeViewModel()
        {
            Id = clientId,
            Path = _authenticationManager.GetClientPath(path),
            Auth = await _authenticationManager.GetClientAuthAsync(path, clientId)
        };

        return View(model);
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
        => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
