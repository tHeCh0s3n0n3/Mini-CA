using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace Backend.Controllers;

public class DiagController : Controller
{
    [Route("diag")]
    public IActionResult Index()
    {
        var model = new
        {
            IsAuthenticated = User.Identity?.IsAuthenticated,
            Name = User.Identity?.Name,
            AuthenticationType = User.Identity?.AuthenticationType,
            Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList(),
            Headers = Request.Headers.Select(h => new { h.Key, Value = h.Value.ToString() }).ToList(),
            Cookies = Request.Cookies.Select(c => new { c.Key, c.Value }).ToList(),
            Scheme = Request.Scheme,
            Host = Request.Host.Value,
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString()
        };

        return Json(model);
    }
}
