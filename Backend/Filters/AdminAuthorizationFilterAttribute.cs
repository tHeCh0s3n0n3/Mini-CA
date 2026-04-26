using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;

namespace Backend.Filters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AdminAuthorizationFilterAttribute : Attribute, IAuthorizationFilter
{
    private readonly IConfiguration _configuration;

    public AdminAuthorizationFilterAttribute(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var configuredAdminGroups = _configuration.GetSection("Authentik:AdminGroups").Get<string[]>() ?? new[] { "admin" };
        if (configuredAdminGroups.Length == 0)
        {
            configuredAdminGroups = new[] { "admin" };
        }

        var groups = context.HttpContext.User.FindAll("groups").Select(c => c.Value).ToList();

        // Also check if they are comma separated in a single claim
        var commaSeparatedGroups = context.HttpContext.User.FindFirstValue("groups");
        if (!string.IsNullOrEmpty(commaSeparatedGroups))
        {
            groups.AddRange(commaSeparatedGroups.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(g => g.Trim()));
        }

        if (!groups.Intersect(configuredAdminGroups, StringComparer.OrdinalIgnoreCase).Any())
        {
            context.Result = new RedirectToRouteResult(
                new RouteValueDictionary(new
                {
                    action = "Error",
                    controller = "Error"
                })
            );
            return;
        }
    }
}
