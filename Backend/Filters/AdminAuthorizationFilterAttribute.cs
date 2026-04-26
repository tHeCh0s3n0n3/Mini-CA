#nullable enable
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Routing;

namespace Backend.Filters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AdminAuthorizationFilterAttribute : Attribute, IAuthorizationFilter
{
    private readonly string[] _adminGroups;

    public AdminAuthorizationFilterAttribute(IConfiguration configuration)
    {
        _adminGroups = configuration.GetSection("Authentik:AdminGroups").Get<string[]>() ?? new[] { "admin" };
        if (_adminGroups.Length == 0)
        {
            _adminGroups = new[] { "admin" };
        }
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var userGroups = context.HttpContext.User.FindAll("groups")
            .SelectMany(c => c.Value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            .Select(g => g.Trim());

        if (!userGroups.Any(g => _adminGroups.Contains(g, StringComparer.OrdinalIgnoreCase)))
        {
            context.Result = new RedirectToRouteResult(
                new RouteValueDictionary(new
                {
                    action = "Error",
                    controller = "Home"
                })
            );
        }
    }
}
