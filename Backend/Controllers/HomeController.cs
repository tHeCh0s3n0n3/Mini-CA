using AspNet.Security.OAuth.Nextcloud;
using Backend.Models;
using Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace Backend.Controllers;

public class HomeController : Controller
{
    public HomeController() { }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    [AllowAnonymous]
    public IActionResult LogInWithNextcloud(string returnUrl = "/")
    {
        AuthenticationProperties props = new()
        {
            RedirectUri = Url.Action("NextcloudSigninCallback"),
            Items =
            {
                { "returnUrl", returnUrl }
            }
        };
        return Challenge(props, NextcloudIdentityProviderDefaults.SchemeName);
    }


#pragma warning disable CS8604 // Possible null reference argument.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
    [AllowAnonymous]
    [Route("/signin-nextcloud")]
    public async Task<IActionResult> NextcloudSigninCallback()
    {
        // read google identity from the temporary cookie
        AuthenticateResult? result
            = await HttpContext.AuthenticateAsync(NextcloudAuthenticationDefaults.AuthenticationScheme);

        //var externalClaims = result.Principal.Claims.ToList();

        //var subjectIdClaim = externalClaims.FirstOrDefault(
        //    x => x.Type == ClaimTypes.NameIdentifier);
        //var subjectValue = subjectIdClaim.Value;

        //var user = userRepository.GetByGoogleId(subjectValue);

        //var claims = new List<Claim>
        //{
        //    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        //    new Claim(ClaimTypes.Name, user.Name),
        //    new Claim(ClaimTypes.Role, user.Role),
        //    new Claim("FavoriteColor", user.FavoriteColor)
        //};

        //var identity = new ClaimsIdentity(claims,
        //    CookieAuthenticationDefaults.AuthenticationScheme);
        //var principal = new ClaimsPrincipal(identity);
        ClaimsPrincipal? principal = result.Principal;

        // delete temporary cookie used during google authentication
        //await HttpContext.SignOutAsync(
        //    NextcloudIdentityProviderDefaults.SchemeName);

        await HttpContext.SignInAsync(
            NextcloudIdentityProviderDefaults.SchemeName, principal);

        //await HttpContext.SignInAsync(
        //    CookieAuthenticationDefaults.AuthenticationScheme, principal);

        return LocalRedirect(result.Properties.Items["returnUrl"]);
    }
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8604 // Possible null reference argument.

}
