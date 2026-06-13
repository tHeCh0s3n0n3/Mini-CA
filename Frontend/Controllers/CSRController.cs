using Frontend.Models;
using Microsoft.AspNetCore.Mvc;
using DAL.Models;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Serilog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
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

    public async Task<IActionResult> Generate(Guid? copyId)
    {
        if (copyId.HasValue)
        {
            var userId = User.Identity?.Name;
            var csr = await _db.CSRs.FirstOrDefaultAsync(c => c.Id == new CSRId(copyId.Value) && c.UserId == userId);
            if (csr != null)
            {
                var viewModel = new CreateCSRViewModel
                {
                    CommonName = csr.CommonName,
                    Organization = csr.Organization,
                    OrganizationUnitName = csr.OrganizationUnitName,
                    CountryCode = csr.CountryCode,
                    Locality = csr.Locality,
                    State = csr.State,
                    EMailAddress = csr.EMailAddress
                };

                // Populate alternate names (SANs) from the existing CSR record
                try
                {
                    var pkcs10 = Common.Certificate.ImportCSR(csr.FileContents);
                    var typedSans = Common.Certificate.GetTypedSANs(pkcs10);
                    viewModel.AlternateNames = typedSans.Select(san => new SanItem 
                    { 
                        Type = san.TagNo, 
                        Value = san.Name 
                    }).ToList();
                }
                catch
                {
                    // Fallback to AlternateNamesList if parsing fails
                    viewModel.AlternateNames = csr.AlternateNamesList.Select(val => new SanItem
                    {
                        Type = Common.Certificate.AutoDetectSanType(val),
                        Value = val
                    }).ToList();
                }

                // Populate key usages/purposes from the existing CSR extensions if possible
                try
                {
                    var pkcs10 = Common.Certificate.ImportCSR(csr.FileContents);
                    var attr = pkcs10.GetCertificationRequestInfo().Attributes;
                    if (attr != null)
                    {
                        for (int i = 0; i != attr.Count; i++)
                        {
                            var pkcsAttr = AttributePkcs.GetInstance(attr[i]);
                            if (pkcsAttr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                            {
                                var extensions = X509Extensions.GetInstance(pkcsAttr.AttrValues[0]);

                                // Key Usage
                                var kuExt = extensions.GetExtension(X509Extensions.KeyUsage);
                                if (kuExt != null)
                                {
                                    var ku = KeyUsage.GetInstance(kuExt.GetParsedValue());
                                    int bits = ku.PadBits == 0 ? ku.GetBytes()[0] : ku.GetBytes()[0] & (0xff << ku.PadBits);

                                    viewModel.UsageDigitalSignature = (bits & KeyUsage.DigitalSignature) != 0;
                                    viewModel.UsageNonRepudiation = (bits & KeyUsage.NonRepudiation) != 0;
                                    viewModel.UsageKeyEncipherment = (bits & KeyUsage.KeyEncipherment) != 0;
                                    viewModel.UsageDataEncipherment = (bits & KeyUsage.DataEncipherment) != 0;
                                    viewModel.UsageKeyAgreement = (bits & KeyUsage.KeyAgreement) != 0;
                                    viewModel.UsageKeyCertSigning = (bits & KeyUsage.KeyCertSign) != 0;
                                    viewModel.UsageCRLSigning = (bits & KeyUsage.CrlSign) != 0;
                                    viewModel.UsageEncipherOnly = (bits & KeyUsage.EncipherOnly) != 0;
                                    viewModel.UsageDecipherOnly = (bits & KeyUsage.DecipherOnly) != 0;
                                }

                                // EKU
                                var ekuExt = extensions.GetExtension(X509Extensions.ExtendedKeyUsage);
                                if (ekuExt != null)
                                {
                                    var eku = ExtendedKeyUsage.GetInstance(ekuExt.GetParsedValue());
                                    
                                    // Reset defaults first
                                    viewModel.PurposeServerAuth = false;
                                    viewModel.UsageDigitalSignature = false;
                                    viewModel.UsageKeyEncipherment = false;

                                    foreach (var purpose in eku.GetAllUsages())
                                    {
                                        if (purpose.Equals(KeyPurposeID.AnyExtendedKeyUsage)) viewModel.PurposeAll = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPServerAuth)) viewModel.PurposeServerAuth = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPClientAuth)) viewModel.PurposeClientAuth = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPCodeSigning)) viewModel.PurposeCodeSigning = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPEmailProtection)) viewModel.PurposeEMailProtection = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPIpsecEndSystem)) viewModel.PurposeIPsecEndSystem = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPIpsecTunnel)) viewModel.PurposeIPsecTunnel = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPIpsecUser)) viewModel.PurposeIPsecUser = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPTimeStamping)) viewModel.PurposeTimeStamping = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPOcspSigning)) viewModel.PurposeOCSPSigning = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPSmartCardLogon)) viewModel.PurposeSmartCardLogon = true;
                                        if (purpose.Equals(KeyPurposeID.IdKPMacAddress)) viewModel.PurposeMACAddress = true;
                                    }
                                }
                            }
                        }
                    }
                }
                catch
                {
                    // Fallback to default usages/purposes
                }

                return View(viewModel);
            }
        }
        return View(new CreateCSRViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Generate(CreateCSRViewModel model)
    {
        if (ModelState.IsValid)
        {
            if (!string.IsNullOrWhiteSpace(model.CommonName))
            {
                bool cnExists = model.AlternateNames?.Any(s => string.Equals(s.Value?.Trim(), model.CommonName.Trim(), StringComparison.OrdinalIgnoreCase)) ?? false;
                if (!cnExists)
                {
                    int detectedType = Common.Certificate.AutoDetectSanType(model.CommonName);
                    model.AlternateNames ??= [];
                    model.AlternateNames.Add(new SanItem { Type = detectedType, Value = model.CommonName.Trim() });
                }
            }

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
