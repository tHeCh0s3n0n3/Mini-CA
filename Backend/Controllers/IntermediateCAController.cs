#nullable enable
using Backend.Filters;
using Backend.Models;
using DAL;
using DAL.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Serilog;

namespace Backend.Controllers;

[Authorize]
[TypeFilter(typeof(AdminAuthorizationFilterAttribute))]
public class IntermediateCAController : Controller
{
    private readonly DB _db;
    private readonly CACertSettings _caCertSettings;

    public IntermediateCAController(DB db, IOptions<CACertSettings> caCertSettings)
    {
        _db = db;
        _caCertSettings = caCertSettings.Value;
    }

    // GET: IntermediateCA
    public async Task<IActionResult> Index()
    {
        var model = await _db.IntermediateCAs
                             .OrderByDescending(c => c.SubmittedOn)
                             .ToListAsync();
        return View(model);
    }

    // GET: IntermediateCA/Create
    public IActionResult Create()
    {
        return View(new CreateCSRViewModel());
    }

    // POST: IntermediateCA/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(CreateCSRViewModel model)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var usages = new List<int> { KeyUsage.KeyCertSign, KeyUsage.CrlSign };
                var (csrPem, keyPem) = Common.Certificate.GenerateCSR(
                    model.CommonName,
                    model.Organization,
                    model.OrganizationUnitName ?? "",
                    model.CountryCode,
                    model.Locality ?? "",
                    model.State ?? "",
                    model.EMailAddress,
                    new List<(int TagNo, string Value)>(),
                    usages,
                    new List<KeyPurposeID>()
                );

                string keyString = Encoding.UTF8.GetString(keyPem);
                string encryptedKey = Common.Encryption.Encrypt(keyString);

                var intermediateCA = new IntermediateCA
                {
                    CommonName = model.CommonName,
                    Organization = model.Organization,
                    OrganizationUnitName = model.OrganizationUnitName ?? "",
                    CountryCode = model.CountryCode,
                    Locality = model.Locality ?? "",
                    State = model.State ?? "",
                    EMailAddress = model.EMailAddress,
                    CsrFileContents = csrPem,
                    FileName = $"{model.CommonName.Replace(" ", "_")}_req.csr",
                    EncryptedPrivateKey = encryptedKey,
                    IsSigned = false,
                    SubmittedOn = DateTime.UtcNow
                };

                _db.IntermediateCAs.Add(intermediateCA);

                var audit = new AuditLog
                {
                    Actor = User.Identity?.Name ?? "Unknown Admin",
                    Action = "Generate Intermediate CA Request",
                    Subject = model.CommonName,
                    Timestamp = DateTime.UtcNow,
                    Details = $"Generated CSR & Key for Intermediate CA. Subject: CN={model.CommonName}, O={model.Organization}, C={model.CountryCode}"
                };
                _db.AuditLogs.Add(audit);

                await _db.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Error generating CSR: " + ex.Message);
            }
        }
        return View(model);
    }

    // GET: IntermediateCA/Upload
    public IActionResult Upload()
    {
        return View(new UploadFileModel());
    }

    // POST: IntermediateCA/Upload
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Upload(UploadFileModel model)
    {
        if (ModelState.IsValid && model.FormFile != null)
        {
            try
            {
                using var ms = new MemoryStream();
                await model.FormFile.CopyToAsync(ms);
                byte[] fileBytes = ms.ToArray();

                string csrString = Encoding.UTF8.GetString(fileBytes);
                // Ensure it is a valid CSR
                Pkcs10CertificationRequest pkcs10 = Common.Certificate.ImportCSR(fileBytes);
                var info = pkcs10.GetCertificationRequestInfo();

                var intermediateCA = new IntermediateCA
                {
                    CsrFileContents = fileBytes,
                    FileName = model.FormFile.FileName,
                    IsSigned = false,
                    SubmittedOn = DateTime.UtcNow,
                    CommonName = "",
                    Organization = "",
                    CountryCode = "AE",
                    EMailAddress = ""
                };

                var subject = info.Subject;
                foreach (DerObjectIdentifier oid in CSR.ObjectIdentifiers.Keys)
                {
                    var propName = CSR.ObjectIdentifiers[oid];
                    var values = subject.GetValueList(oid);
                    if (values.Count > 0)
                    {
                        var val = values[0]?.ToString() ?? "";
                        intermediateCA.SetProperty(propName, val);
                    }
                }

                _db.IntermediateCAs.Add(intermediateCA);

                var audit = new AuditLog
                {
                    Actor = User.Identity?.Name ?? "Unknown Admin",
                    Action = "Upload Intermediate CA CSR",
                    Subject = intermediateCA.CommonName,
                    Timestamp = DateTime.UtcNow,
                    Details = $"Uploaded CSR file {model.FormFile.FileName} for Intermediate CA."
                };
                _db.AuditLogs.Add(audit);

                await _db.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Failed to parse CSR: " + ex.Message);
            }
        }
        return View(model);
    }

    // GET: IntermediateCA/Sign/5
    public async Task<IActionResult> Sign(Guid? id)
    {
        if (id is null || !id.HasValue)
        {
            return NotFound();
        }

        var ca = await _db.IntermediateCAs.FindAsync(new IntermediateCAId(id.Value));
        if (ca is null)
        {
            return NotFound();
        }

        if (ca.IsSigned)
        {
            return BadRequest("Intermediate CA has already been signed.");
        }

        // Load Root CA Cert to get Expiry Limit
        var rootCert = Common.Certificate.ImportCACert(_caCertSettings.CertFilePath);
        var rootExpiry = rootCert.NotAfter;

        // Default to Min(Now + 5 years, Root Expiry)
        var defaultExpiry = DateTime.UtcNow.AddYears(5);
        if (defaultExpiry > rootExpiry)
        {
            defaultExpiry = rootExpiry;
        }

        var viewModel = new SignIntermediateCAViewModel
        {
            Id = ca.Id.Value,
            CommonName = ca.CommonName,
            Organization = ca.Organization,
            OrganizationUnitName = ca.OrganizationUnitName ?? "",
            CountryCode = ca.CountryCode,
            Locality = ca.Locality ?? "",
            State = ca.State ?? "",
            EMailAddress = ca.EMailAddress,
            ExpieryDate = defaultExpiry,
            MaxExpiryDate = rootExpiry
        };

        return View(viewModel);
    }

    // POST: IntermediateCA/Sign/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Sign(Guid id, [FromForm] SignIntermediateCAViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var ca = await _db.IntermediateCAs.FindAsync(new IntermediateCAId(id));
        if (ca is null)
        {
            return NotFound();
        }

        if (ca.IsSigned)
        {
            return BadRequest("Intermediate CA has already been signed.");
        }

        try
        {
            // Load Root CA Cert to validate expiry date
            var rootCert = Common.Certificate.ImportCACert(_caCertSettings.CertFilePath);
            var rootExpiry = rootCert.NotAfter;

            if (model.ExpieryDate > rootExpiry)
            {
                ModelState.AddModelError(nameof(model.ExpieryDate), $"The expiry date cannot exceed the Root CA's expiry date ({rootExpiry:yyyy-MM-dd HH:mm:ss} Z).");
                model.MaxExpiryDate = rootExpiry;
                return View(model);
            }

            // Grab the Root CA key
            var rootKey = Common.Certificate.ImportCAKey(_caCertSettings.CertKeyFilePath, _caCertSettings.CertKeyPasswordFilePath);

            // Import intermediate CA CSR
            var csr = Common.Certificate.ImportCSR(ca.CsrFileContents);

            // Intermediate CAs must have key usage KeyCertSign and CrlSign
            var keyUsages = new List<int> { KeyUsage.KeyCertSign, KeyUsage.CrlSign };
            var keyPurposes = new List<KeyPurposeID>();

            // Calculate validity years (approximate from days)
            int validityYears = (int)Math.Max(1, Math.Round((model.ExpieryDate - DateTime.UtcNow).TotalDays / 365.0));

            // Sign the certificate
            var signedCert = Common.Certificate.SignCSR(csr, rootCert, rootKey, validityYears, keyUsages, keyPurposes, null);
            
            // Re-enforce exact dates requested (SignCSR logic constructs validity from years, so we override it with precise dates)
            // Let's set NotBefore/NotAfter fields directly in database record
            string newCertFileContents = Common.Certificate.CertToFile(signedCert);
            byte[] certBytes = Encoding.UTF8.GetBytes(newCertFileContents);

            ca.Certificate = certBytes;
            ca.IsSigned = true;
            ca.SignedOn = DateTime.UtcNow;
            ca.NotBefore = signedCert.NotBefore;
            ca.NotAfter = model.ExpieryDate; // Store the exact requested date

            _db.IntermediateCAs.Update(ca);

            var audit = new AuditLog
            {
                Actor = User.Identity?.Name ?? "Unknown Admin",
                Action = "Sign Intermediate CA",
                Subject = ca.CommonName,
                Timestamp = DateTime.UtcNow,
                Details = $"Signed Intermediate CA. Valid until {model.ExpieryDate:yyyy-MM-dd HH:mm:ss} Z."
            };
            _db.AuditLogs.Add(audit);

            await _db.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            ModelState.AddModelError(string.Empty, "Failed to sign Intermediate CA: " + ex.Message);
            model.MaxExpiryDate = Common.Certificate.ImportCACert(_caCertSettings.CertFilePath).NotAfter;
        }

        return View(model);
    }

    // GET: IntermediateCA/DownloadCertificate/5
    public async Task<IActionResult> DownloadCertificate(Guid id)
    {
        var ca = await _db.IntermediateCAs.FindAsync(new IntermediateCAId(id));
        if (ca is null || ca.Certificate is null)
        {
            return NotFound();
        }

        return File(ca.Certificate, "application/x-x509-ca-cert", $"{ca.CommonName.Replace(" ", "_")}.crt");
    }

    // GET: IntermediateCA/DownloadKey/5
    public async Task<IActionResult> DownloadKey(Guid id)
    {
        var ca = await _db.IntermediateCAs.FindAsync(new IntermediateCAId(id));
        if (ca is null || string.IsNullOrEmpty(ca.EncryptedPrivateKey))
        {
            return NotFound();
        }

        string decryptedKey = Common.Encryption.Decrypt(ca.EncryptedPrivateKey);
        var keyBytes = Encoding.UTF8.GetBytes(decryptedKey);

        return File(keyBytes, "application/octet-stream", $"{ca.CommonName.Replace(" ", "_")}.key");
    }

    // POST: IntermediateCA/Delete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id)
    {
        var ca = await _db.IntermediateCAs.FindAsync(new IntermediateCAId(id));
        if (ca is not null)
        {
            _db.IntermediateCAs.Remove(ca);

            var audit = new AuditLog
            {
                Actor = User.Identity?.Name ?? "Unknown Admin",
                Action = "Delete Intermediate CA",
                Subject = ca.CommonName,
                Timestamp = DateTime.UtcNow,
                Details = $"Deleted Intermediate CA request/cert for {ca.CommonName}."
            };
            _db.AuditLogs.Add(audit);

            await _db.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index));
    }
}
