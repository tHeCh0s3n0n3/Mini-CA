using Backend.Filters;
using Backend.Models;
using DAL;
using DAL.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Serilog;
using System.Collections;

namespace Backend.Controllers;

[Authorize]
[TypeFilter(typeof(AdminAuthorizationFilterAttribute))]
public class CSRController : Controller
{
    private readonly DB _db;
    private readonly CACertSettings _caCertSettings;

    public CSRController(DB db, IOptions<CACertSettings> caCertSettings)
    {
        _db = db;
        _caCertSettings = caCertSettings.Value;

        if (HttpContext?.User?.Identity is not null
            && HttpContext.User.Identity.IsAuthenticated)
        {

        }
    }

    // GET: CSR
    public async Task<IActionResult> Index()
    {
        List<CSR> csrs = await _db.CSRs.ToListAsync();
        List<CSRIndexViewModel> model = [];
        foreach(CSR csr in csrs)
        {
            SignedCSR? signedCSR = null;
            if (csr.IsSigned)
            {
                signedCSR
                    = await _db.SignedCSRs.FirstOrDefaultAsync(s => s.OriginalRequestId.Equals(csr.Id));
            }
            model.Add(new CSRIndexViewModel(csr, signedCSR));
        }
        return View(model);
    }

    // GET: CSR/Details/5
    public async Task<IActionResult> Details(Guid? id)
    {
        if (id is null || !id.HasValue)
        {
            return NotFound();
        }

        CSR? csr = await _db.CSRs.FindAsync(new CSRId(id.Value));
        SignedCSR? signedCSR = await _db.SignedCSRs.FirstOrDefaultAsync(m => m.OriginalRequestId.Equals(new CSRId(id.Value)));
        return csr is null
               ? NotFound()
#pragma warning disable CS8604 // Possible null reference argument.
               : View(new CSRDetailViewModel(csr, signedCSR));
#pragma warning restore CS8604 // Possible null reference argument.
    }

    // GET: CSR/Delete/5
    public async Task<IActionResult> Delete(Guid? id)
    {
        if (id is null || !id.HasValue)
        {
            return NotFound();
        }

        CSR? csr = await _db.CSRs.FindAsync(new CSRId(id.Value));

        if (csr is null)
        {
            return NotFound();
        }

        return View(csr);
    }

    // POST: CSR/Delete/5
    [HttpPost, ActionName("Delete")]
    //[ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(Guid id)
    {
        CSR? csr = await _db.CSRs.FindAsync(new CSRId(id));
        if (csr is not null)
        {
            _db.CSRs.Remove(csr);
            await _db.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index));
    }

    // GET: CSR/Create
    public IActionResult Create()
    {
        return View(new CreateCSRViewModel());
    }

    // POST: CSR/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(CreateCSRViewModel model)
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

            return View("CreateSuccess", new CSRGeneratedSuccessViewModel 
            { 
                CSR = csr, 
                PrivateKeyPem = Encoding.UTF8.GetString(keyPem) 
            });
        }
        return View(model);
    }


    public IActionResult Upload()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Upload(UploadFileModel model)
    {
        Log.Information("Started upload function in Backend. File present: {FilePresent}", model?.FormFile != null);

        try
        {
            if (model?.FormFile == null || !ModelState.IsValid)
            {
                if (model?.FormFile == null) Log.Warning("Upload failed: FormFile is null.");
                return View();
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

                Log.Information("Processing file in Backend: {FileName}, Size: {Size}", parsedCSR.FileName, parsedCSR.FileContents.Length);

                Pkcs10CertificationRequest csr;

                try
                {
                    csr = Common.Certificate.ImportCSR(parsedCSR.FileContents);
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Failed to parse CSR: {ex.Message}");
                    return View();
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
            
            _db.Add<CSR>(parsedCSR);
            await _db.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error uploading CSR in Backend");
            ModelState.AddModelError("", $"An unexpected error occurred: {ex.Message}");
            return View();
        }
    }


    // GET: CSR/Process/5
    public async Task<IActionResult> Process(Guid? id)
    {
        if (id is null || !id.HasValue)
        {
            return NotFound();
        }

        CSR? csr = await _db.CSRs.FindAsync(new CSRId(id.Value));

        if (csr is null)
        {
            return NotFound();
        }

        if (csr.IsSigned)
        {
            return BadRequest("Requst has already been processed.");
        }

        return View(new ProcessViewModel(csr));
    }
    
    // POST: CSR/Process/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Process(Guid Id
                                             , [FromForm] ProcessViewModel processViewModel)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }

        CSR? dbCSR = await _db.CSRs.FindAsync(processViewModel.OriginalRequestId);
        if (dbCSR is not null)
        {
            // Get the certificates
            List<int> keyUsages = processViewModel.RequestedKeyUsages;
            List<Org.BouncyCastle.Asn1.X509.KeyPurposeID> keyPurposeIDs = processViewModel.RequestedKeyPurposes;

            // Read the CSR
            //Console.WriteLine("Reading the CSR...");
            Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest csr = Common.Certificate.ImportCSR(dbCSR.FileContents);

            // Grab the CA cert and its key
            Org.BouncyCastle.X509.X509Certificate caCert = Common.Certificate.ImportCACert(_caCertSettings.CertFilePath);
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKey
                = Common.Certificate.ImportCAKey(_caCertSettings.CertKeyFilePath
                                                 , _caCertSettings.CertKeyPasswordFilePath);

            // Sign the cert
            //Console.WriteLine("Signing the CSR...");
            var sans = processViewModel.AlternateNames?.Select(s => (s.Type, s.Value)).ToList();
            Log.Information("Signing CSR with {Count} SAN overrides", sans?.Count ?? 0);
            if (sans != null)
            {
                foreach (var s in sans)
                {
                    Log.Information("SAN Override: Type {Type}, Value {Value}", s.Type, s.Value);
                }
            }
            Org.BouncyCastle.X509.X509Certificate signedCert = Common.Certificate.SignCSR(csr, caCert, caKey, 1, keyUsages, keyPurposeIDs, sans);
            string newCertFileContents = Common.Certificate.CertToFile(signedCert);

            // Save signed cert
            SignedCSR signedCSR = new(dbCSR.Id
                                      , DateTime.UtcNow
                                      , Encoding.UTF8.GetBytes(newCertFileContents)
                                      , DateTime.UtcNow
                                      , processViewModel.ExpieryDate);
            dbCSR.IsSigned = true;

            _db.CSRs.Update(dbCSR);
            _db.SignedCSRs.Add(signedCSR);

            // Audit Log
            var audit = new AuditLog
            {
                Actor = User.Identity?.Name ?? "Unknown Admin",
                Action = "Manual Sign",
                Subject = csr.GetCertificationRequestInfo().Subject.ToString(),
                Timestamp = DateTime.UtcNow,
                Details = $"Signed manually from UI. Valid until {processViewModel.ExpieryDate:yyyy-MM-dd HH:mm:ss} Z"
            };
            _db.AuditLogs.Add(audit);

            await _db.SaveChangesAsync();
        }

        return RedirectToAction(nameof(Index));
    }

    public async Task<IActionResult> DownloadKey(Guid id)
    {
        var csr = await _db.CSRs.FindAsync(new CSRId(id));
        
        if (csr == null || string.IsNullOrEmpty(csr.EncryptedPrivateKey)) 
            return NotFound("Private key not found.");

        string decryptedKey = Common.Encryption.Decrypt(csr.EncryptedPrivateKey);
        var keyBytes = Encoding.UTF8.GetBytes(decryptedKey);

        return File(keyBytes, "application/octet-stream", $"{csr.CommonName}.key");
    }

    [HttpGet]
    public async Task<IActionResult> DownloadCertificate(Guid Id)
    {
        SignedCSR? signedCSR = await _db.SignedCSRs.FindAsync(new SignedCSRId(Id));

        if (signedCSR is null)
        {
            return NotFound();
        }

        CSR? origCSR = await _db.CSRs.FindAsync(signedCSR.OriginalRequestId);
        if (origCSR is null)
        {
            return NotFound();
        }

        return File(signedCSR.Certificate
                    , "application/x-x509-user-cert"
                    , $"{origCSR.CommonName}_Exp_{signedCSR.NotAfter:yyyy-MM-dd}.crt"
                    , new DateTimeOffset(signedCSR.SignedOn)
                    , new Microsoft.Net.Http.Headers.EntityTagHeaderValue(
                        new Microsoft.Extensions.Primitives.StringSegment($"\"{signedCSR.Id:N}\"")
                        , true)
                    );
    }

    //private bool CSRExists(Guid id)
    //{
    //    return _db.CSRs.Any(e => e.Id.Equals(new CSRId(id)));
    //}
}