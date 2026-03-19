using DAL;
using DAL.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Common;
using System.Security.Cryptography;
using Backend.Filters;

namespace Backend.Controllers;

[Authorize]
[TypeFilter(typeof(AdminAuthorizationFilterAttribute))]
public class AcmeEabController : Controller
{
    private readonly DB _db;
    private readonly IConfiguration _configuration;

    public AcmeEabController(DB db, IConfiguration configuration)
    {
        _db = db;
        _configuration = configuration;
    }

    public async Task<IActionResult> Index()
    {
        var eabs = await _db.AcmeEabs.ToListAsync();
        return View(eabs);
    }

    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(string description, string allowedIdentifierPattern)
    {
        if (string.IsNullOrEmpty(description))
        {
            ModelState.AddModelError("", "Description is required.");
            return View();
        }

        // Generate KID and HMAC Key
        var kid = Guid.NewGuid().ToString("N");
        var hmacKeyBytes = new byte[32];
        RandomNumberGenerator.Fill(hmacKeyBytes);
        var hmacKeyBase64 = Convert.ToBase64String(hmacKeyBytes);

        // Encrypt HMAC Key
        var masterKeyPath = _configuration["Acme:MasterKeyPath"];
        if (string.IsNullOrEmpty(masterKeyPath))
        {
            throw new Exception("Acme:MasterKeyPath is not configured.");
        }
        Encryption.Initialize(masterKeyPath);
        var encryptedHmacKey = Encryption.Encrypt(hmacKeyBase64);

        var eab = new AcmeEab
        {
            KID = kid,
            EncryptedHmacKey = encryptedHmacKey,
            Description = description,
            AllowedIdentifierPattern = allowedIdentifierPattern,
            CreatedAt = DateTime.UtcNow
        };

        _db.AcmeEabs.Add(eab);
        await _db.SaveChangesAsync();

        // Pass KID and unencrypted HMAC key to the success view (Show Once)
        ViewBag.Kid = kid;
        ViewBag.HmacKey = hmacKeyBase64;

        return View("CreateSuccess");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id)
    {
        var eab = await _db.AcmeEabs.FindAsync(new AcmeEabId(id));
        if (eab != null)
        {
            _db.AcmeEabs.Remove(eab);
            await _db.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index));
    }
}
