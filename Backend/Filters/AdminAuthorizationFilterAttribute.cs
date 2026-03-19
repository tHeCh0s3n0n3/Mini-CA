using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

namespace Backend.Filters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AdminAuthorizationFilterAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var groups = context.HttpContext.User.FindAll("groups").Select(c => c.Value).ToList();

        // Also check if they are comma separated in a single claim
        var commaSeparatedGroups = context.HttpContext.User.FindFirstValue("groups");
        if (!string.IsNullOrEmpty(commaSeparatedGroups))
        {
            groups.AddRange(commaSeparatedGroups.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(g => g.Trim()));
        }

        if (!groups.Any(g => g.Equals("admin", StringComparison.OrdinalIgnoreCase)))
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
