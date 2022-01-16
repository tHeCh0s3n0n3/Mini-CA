using AspNet.Security.OAuth.Nextcloud;
using Backend.Models;
using Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Backend.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

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
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action("NextcloudSigninCallback"),
                Items =
                {
                    { "returnUrl", returnUrl }
                }
            };
            return Challenge(props, NextcloudIdentityProviderDefaults.SchemeName);
        }

        [AllowAnonymous]
        [Route("/signin-nextcloud")]
        public async Task<IActionResult> NextcloudSigninCallback()
        {
            // read google identity from the temporary cookie
            var result
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
            var principal = result.Principal;

            // delete temporary cookie used during google authentication
            //await HttpContext.SignOutAsync(
            //    NextcloudIdentityProviderDefaults.SchemeName);

            await HttpContext.SignInAsync(
                NextcloudIdentityProviderDefaults.SchemeName, principal);
             
            //await HttpContext.SignInAsync(
            //    CookieAuthenticationDefaults.AuthenticationScheme, principal);

            return LocalRedirect(result.Properties.Items["returnUrl"]);
        }
    }
}
