using Frontend.Models;
using Microsoft.AspNetCore.Mvc;
using DAL.Models;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Serilog;
using Org.BouncyCastle.Asn1;
using System.Collections;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace Frontend.Controllers;

[Authorize]
public class CSRController : Controller
{
    private readonly DAL.DB _db;
    private readonly IConfiguration _configuration;

    public CSRController(DAL.DB db, IConfiguration configuration)
    {
        Log.Information("Entered CSRController");
        _db = db;
        _configuration = configuration;
    }

    public async Task<IActionResult> Index()
    {
        Log.Information("Showing CSR Dashboard.");
        
        var userId = User.Identity?.Name;
        var csrs = await _db.CSRs
                            .Where(c => c.UserId == userId)
                            .OrderByDescending(c => c.SubmittedOn)
                            .ToListAsync();

        var model = new UserDashboardViewModel();
        foreach (var csr in csrs)
        {
            var signed = await _db.SignedCSRs.FirstOrDefaultAsync(s => s.OriginalRequestId == csr.Id);
            model.CSRs.Add(new CSRItemViewModel(csr, signed));
        }

        return View(model);
    }

    public IActionResult Generate()
    {
        return View(new CreateCSRViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Generate(CreateCSRViewModel model)
    {
        if (ModelState.IsValid)
        {
            var sans = model.AlternateNames?.Select(s => (s.Type, s.Value)).ToList() ?? [];
            var (csrPem, keyPem) = Common.Certificate.GenerateCSR(
                model.CommonName, 
                model.Organization, 
                model.OrganizationUnitName ?? "", 
                model.CountryCode, 
                model.Locality ?? "", 
                model.State ?? "", 
                model.EMailAddress, 
                sans, 
                model.RequestedKeyUsages, 
                model.RequestedKeyPurposes);

            string keyString = Encoding.UTF8.GetString(keyPem);
            string encryptedKey = Common.Encryption.Encrypt(keyString);

            CSR csr = new()
            {
                CommonName = model.CommonName,
                Organization = model.Organization,
                OrganizationUnitName = model.OrganizationUnitName ?? "",
                CountryCode = model.CountryCode,
                Locality = model.Locality ?? "",
                State = model.State ?? "",
                EMailAddress = model.EMailAddress,
                AlternateNamesList = model.AlternateNames?.Select(s => s.Value).ToList() ?? [],
                FileContents = csrPem,
                FileName = $"{model.CommonName}.csr",
                SubmittedOn = DateTime.UtcNow,
                IsSigned = false,
                UserId = User.Identity?.Name,
                EncryptedPrivateKey = encryptedKey
            };

            _db.CSRs.Add(csr);
            await _db.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        return View(model);
    }

    public async Task<IActionResult> DownloadKey(Guid id)
    {
        var userId = User.Identity?.Name;
        var csr = await _db.CSRs.FirstOrDefaultAsync(c => c.Id == new CSRId(id) && c.UserId == userId);
        
        if (csr == null || string.IsNullOrEmpty(csr.EncryptedPrivateKey)) 
            return NotFound("Private key not found or access denied.");

        string decryptedKey = Common.Encryption.Decrypt(csr.EncryptedPrivateKey);
        var keyBytes = Encoding.UTF8.GetBytes(decryptedKey);

        return File(keyBytes, "application/octet-stream", $"{csr.CommonName}.key");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Upload([FromForm(Name = "UploadModel")] UploadFileModel model)
    {
        Log.Information("Started upload function. File present: {FilePresent}", model?.FormFile != null);

        try
        {
            if (model?.FormFile == null || !ModelState.IsValid)
            {
                if (model?.FormFile == null) Log.Warning("Upload failed: FormFile is null.");
                foreach (var state in ModelState)
                {
                    foreach (var error in state.Value.Errors)
                    {
                        Log.Warning("ModelState Error in {Key}: {ErrorMessage}", state.Key, error.ErrorMessage);
                    }
                }
                return RedirectToAction("Index");
            }

            CSR parsedCSR = new();
            parsedCSR.UserId = User.Identity?.Name;

            if (model.FormFile.Length > 0)
            {
                parsedCSR.FileName = model.FormFile.FileName;
                parsedCSR.IsSigned = false;
                parsedCSR.SubmittedOn = DateTime.UtcNow;

                using Stream s = model.FormFile.OpenReadStream();
                using (MemoryStream ms = new())
                {
                    await s.CopyToAsync(ms);
                    parsedCSR.FileContents = ms.ToArray();
                }

                Log.Information("Processing file: {FileName}, Size: {Size}", parsedCSR.FileName, parsedCSR.FileContents.Length);


                Pkcs10CertificationRequest csr;

                try
                {
                    csr = Common.Certificate.ImportCSR(parsedCSR.FileContents);
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }

                CertificationRequestInfo csrInfo = csr.GetCertificationRequestInfo();

                foreach (KeyValuePair<DerObjectIdentifier, string> item in CSR.ObjectIdentifiers)
                {
                    IList valueResult = csrInfo.Subject.GetValueList(item.Key);
                    if (valueResult.Count == 1)
                    {
                        if (valueResult[0] is null)
                        {
                            continue;
                        }
                        parsedCSR.SetProperty(item.Value, $"{valueResult[0]}");
                    }
                }

                List<string> alternateNames = Common.Certificate
                                                    .GetSANs(csr)
                                                    .ToList();
                parsedCSR.AlternateNamesList = alternateNames;
            }
            await _db.Database.EnsureCreatedAsync();
            _db.Add<CSR>(parsedCSR);
            await _db.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    public async Task<IActionResult> DownloadPem(Guid id)
    {
        var signed = await _db.SignedCSRs.FirstOrDefaultAsync(s => s.Id == new SignedCSRId(id));
        if (signed == null) return NotFound();

        var csr = await _db.CSRs.FindAsync(signed.OriginalRequestId);
        var fileName = $"{csr?.CommonName ?? "cert"}_Exp_{signed.NotAfter:yyyy-MM-dd}.crt";

        return File(signed.Certificate, "application/x-x509-ca-cert", fileName
                    , new DateTimeOffset(signed.SignedOn)
                    , new Microsoft.Net.Http.Headers.EntityTagHeaderValue(
                        new Microsoft.Extensions.Primitives.StringSegment($"\"{signed.Id:N}\""), true));
    }

    public async Task<IActionResult> DownloadDer(Guid id)
    {
        var signed = await _db.SignedCSRs.FirstOrDefaultAsync(s => s.Id == new SignedCSRId(id));
        if (signed == null) return NotFound();

        var certString = Encoding.UTF8.GetString(signed.Certificate);
        // Remove PEM headers to get raw bytes
        var base64 = certString.Replace("-----BEGIN CERTIFICATE-----", "")
                               .Replace("-----END CERTIFICATE-----", "")
                               .Replace("\r", "").Replace("\n", "");
        var derBytes = Convert.FromBase64String(base64);

        var csr = await _db.CSRs.FindAsync(signed.OriginalRequestId);
        var fileName = $"{csr?.CommonName ?? "cert"}_Exp_{signed.NotAfter:yyyy-MM-dd}.cer";

        return File(derBytes, "application/octet-stream", fileName
                    , new DateTimeOffset(signed.SignedOn)
                    , new Microsoft.Net.Http.Headers.EntityTagHeaderValue(
                        new Microsoft.Extensions.Primitives.StringSegment($"\"{signed.Id:N}\""), true));
    }

    public async Task<IActionResult> DownloadP7b(Guid id)
    {
        var signed = await _db.SignedCSRs.FirstOrDefaultAsync(s => s.Id == new SignedCSRId(id));
        if (signed == null) return NotFound();

        var bcCert = Common.Certificate.ImportCACert(signed.Certificate);
        var caPath = _configuration["CACert:CertFilePath"];
        if (string.IsNullOrEmpty(caPath)) return BadRequest("Root CA not configured.");
        
        var caCert = Common.Certificate.ImportCACert(caPath);
        var p7bBytes = Common.Certificate.CertToP7B(bcCert, caCert);

        var csr = await _db.CSRs.FindAsync(signed.OriginalRequestId);
        var fileName = $"{csr?.CommonName ?? "cert"}_Exp_{signed.NotAfter:yyyy-MM-dd}.p7b";

        return File(p7bBytes, "application/x-pkcs7-certificates", fileName
                    , new DateTimeOffset(signed.SignedOn)
                    , new Microsoft.Net.Http.Headers.EntityTagHeaderValue(
                        new Microsoft.Extensions.Primitives.StringSegment($"\"{signed.Id:N}\""), true));
    }

    public IActionResult DownloadRoot()
    {
        var caPath = _configuration["CACert:CertFilePath"];
        if (string.IsNullOrEmpty(caPath) || !System.IO.File.Exists(caPath)) 
            return NotFound("Root CA file not found.");

        return File(System.IO.File.ReadAllBytes(caPath), "application/x-x509-ca-cert", "minica-root.crt");
    }
}
