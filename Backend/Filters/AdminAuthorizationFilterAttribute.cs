using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Backend.Filters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AdminAuthorizationFilterAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        string? nextcloudGroups
            = context.HttpContext
                .User.Claims.FirstOrDefault(c => c.Type.Equals("urn:nextcloud:groups"))
                            ?.Value;

        if (string.IsNullOrEmpty(nextcloudGroups))
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

        var foundAdmin = false;
        foreach(var group in nextcloudGroups.Split(','))
        {
            if (group.Equals("admin", StringComparison.OrdinalIgnoreCase))
            {
                foundAdmin = true;
            }
        }

        if (!foundAdmin)
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
