using DAL;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Backend.Filters;

namespace Backend.Controllers;

[Authorize]
[TypeFilter(typeof(AdminAuthorizationFilterAttribute))]
public class AuditController : Controller
{
    private readonly DB _db;

    public AuditController(DB db)
    {
        _db = db;
    }

    public async Task<IActionResult> Index()
    {
        var logs = await _db.AuditLogs
                            .OrderByDescending(l => l.Timestamp)
                            .Take(100)
                            .ToListAsync();
        return View(logs);
    }
}
