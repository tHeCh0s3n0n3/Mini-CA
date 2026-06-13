#nullable enable
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
using Org.BouncyCastle.Asn1.X509;
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
    public async Task<IActionResult> Create(Guid? copyId)
    {
        if (copyId.HasValue)
        {
            var csr = await _db.CSRs.FindAsync(new CSRId(copyId.Value));
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

                void PopulateFromCSR(CSR sourceCsr, CreateCSRViewModel vm)
                {
                    // Populate alternate names (SANs) from the existing CSR record
                    try
                    {
                        var pkcs10 = Common.Certificate.ImportCSR(sourceCsr.FileContents);
                        var typedSans = Common.Certificate.GetTypedSANs(pkcs10);
                        vm.AlternateNames = typedSans.Select(san => new SanItem 
                        { 
                            Type = san.TagNo, 
                            Value = san.Name 
                        }).ToList();
                    }
                    catch
                    {
                        // Fallback to AlternateNamesList if parsing fails
                        vm.AlternateNames = sourceCsr.AlternateNamesList.Select(val => new SanItem
                        {
                            Type = Common.Certificate.AutoDetectSanType(val),
                            Value = val
                        }).ToList();
                    }

                    // Populate key usages/purposes from the existing CSR extensions if possible
                    try
                    {
                        var pkcs10 = Common.Certificate.ImportCSR(sourceCsr.FileContents);
                        var attr = pkcs10.GetCertificationRequestInfo().Attributes;
                        if (attr != null)
                        {
                            for (int i = 0; i != attr.Count; i++)
                            {
                                var pkcsAttr = AttributePkcs.GetInstance(attr[i]);
                                if (pkcsAttr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                                {
                                    var extensions = X509Extensions.GetInstance(pkcsAttr.AttrValues[0]);

                                    // Reset defaults first so we only check what is actually requested in the CSR
                                    vm.UsageDigitalSignature = false;
                                    vm.UsageKeyEncipherment = false;
                                    vm.PurposeServerAuth = false;

                                    // Key Usage
                                    var kuExt = extensions.GetExtension(X509Extensions.KeyUsage);
                                    if (kuExt != null)
                                    {
                                        var ku = KeyUsage.GetInstance(kuExt.GetParsedValue());
                                        int bits = ku.PadBits == 0 ? ku.GetBytes()[0] : ku.GetBytes()[0] & (0xff << ku.PadBits);

                                        vm.UsageDigitalSignature = (bits & KeyUsage.DigitalSignature) != 0;
                                        vm.UsageNonRepudiation = (bits & KeyUsage.NonRepudiation) != 0;
                                        vm.UsageKeyEncipherment = (bits & KeyUsage.KeyEncipherment) != 0;
                                        vm.UsageDataEncipherment = (bits & KeyUsage.DataEncipherment) != 0;
                                        vm.UsageKeyAgreement = (bits & KeyUsage.KeyAgreement) != 0;
                                        vm.UsageKeyCertSigning = (bits & KeyUsage.KeyCertSign) != 0;
                                        vm.UsageCRLSigning = (bits & KeyUsage.CrlSign) != 0;
                                        vm.UsageEncipherOnly = (bits & KeyUsage.EncipherOnly) != 0;
                                        vm.UsageDecipherOnly = (bits & KeyUsage.DecipherOnly) != 0;
                                    }

                                    // EKU
                                    var ekuExt = extensions.GetExtension(X509Extensions.ExtendedKeyUsage);
                                    if (ekuExt != null)
                                    {
                                        var eku = ExtendedKeyUsage.GetInstance(ekuExt.GetParsedValue());

                                        foreach (var purpose in eku.GetAllUsages())
                                        {
                                            if (purpose.Equals(KeyPurposeID.AnyExtendedKeyUsage)) vm.PurposeAll = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPServerAuth)) vm.PurposeServerAuth = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPClientAuth)) vm.PurposeClientAuth = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPCodeSigning)) vm.PurposeCodeSigning = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPEmailProtection)) vm.PurposeEMailProtection = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPIpsecEndSystem)) vm.PurposeIPsecEndSystem = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPIpsecTunnel)) vm.PurposeIPsecTunnel = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPIpsecUser)) vm.PurposeIPsecUser = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPTimeStamping)) vm.PurposeTimeStamping = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPOcspSigning)) vm.PurposeOCSPSigning = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPSmartCardLogon)) vm.PurposeSmartCardLogon = true;
                                            if (purpose.Equals(KeyPurposeID.IdKPMacAddress)) vm.PurposeMACAddress = true;
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
                }

                // Check if a signed certificate already exists
                var signedCSR = await _db.SignedCSRs.FirstOrDefaultAsync(s => s.OriginalRequestId == csr.Id);
                if (signedCSR != null)
                {
                    try
                    {
                        var cert = Common.Certificate.ImportCACert(signedCSR.Certificate);

                        // Reset defaults first so we only populate what is actually in the certificate
                        viewModel.UsageDigitalSignature = false;
                        viewModel.UsageKeyEncipherment = false;
                        viewModel.PurposeServerAuth = false;

                        // Populate alternate names (SANs) from the certificate
                        var alternateNames = new List<SanItem>();
                        var sanExtension = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
                        if (sanExtension != null)
                        {
                            var gns = GeneralNames.GetInstance(Asn1Object.FromByteArray(sanExtension.GetOctets()));
                            foreach (var gn in gns.GetNames())
                            {
                                string? name = gn.Name.ToString();
                                if (gn.TagNo == GeneralName.IPAddress)
                                {
                                    var ipOctets = Asn1OctetString.GetInstance(gn.Name).GetOctets();
                                    try
                                    {
                                        name = new System.Net.IPAddress(ipOctets).ToString();
                                    }
                                    catch { }
                                }
                                if (name != null)
                                {
                                    alternateNames.Add(new SanItem { Type = gn.TagNo, Value = name });
                                }
                            }
                        }
                        viewModel.AlternateNames = alternateNames;

                        // Populate Key Usages from the certificate
                        var ku = cert.GetKeyUsage();
                        if (ku != null)
                        {
                            viewModel.UsageDigitalSignature = ku.Length > 0 && ku[0];
                            viewModel.UsageNonRepudiation = ku.Length > 1 && ku[1];
                            viewModel.UsageKeyEncipherment = ku.Length > 2 && ku[2];
                            viewModel.UsageDataEncipherment = ku.Length > 3 && ku[3];
                            viewModel.UsageKeyAgreement = ku.Length > 4 && ku[4];
                            viewModel.UsageKeyCertSigning = ku.Length > 5 && ku[5];
                            viewModel.UsageCRLSigning = ku.Length > 6 && ku[6];
                            viewModel.UsageEncipherOnly = ku.Length > 7 && ku[7];
                            viewModel.UsageDecipherOnly = ku.Length > 8 && ku[8];
                        }

                        // Populate Extended Key Usages/Purposes from the certificate
                        var eku = cert.GetExtendedKeyUsage();
                        if (eku != null)
                        {
                            // Reset defaults first
                            viewModel.PurposeAll = false;
                            viewModel.PurposeServerAuth = false;
                            viewModel.PurposeClientAuth = false;
                            viewModel.PurposeCodeSigning = false;
                            viewModel.PurposeEMailProtection = false;
                            viewModel.PurposeIPsecEndSystem = false;
                            viewModel.PurposeIPsecTunnel = false;
                            viewModel.PurposeIPsecUser = false;
                            viewModel.PurposeTimeStamping = false;
                            viewModel.PurposeOCSPSigning = false;
                            viewModel.PurposeSmartCardLogon = false;
                            viewModel.PurposeMACAddress = false;

                            foreach (DerObjectIdentifier oid in eku)
                            {
                                if (oid.Equals(KeyPurposeID.AnyExtendedKeyUsage)) viewModel.PurposeAll = true;
                                if (oid.Equals(KeyPurposeID.IdKPServerAuth)) viewModel.PurposeServerAuth = true;
                                if (oid.Equals(KeyPurposeID.IdKPClientAuth)) viewModel.PurposeClientAuth = true;
                                if (oid.Equals(KeyPurposeID.IdKPCodeSigning)) viewModel.PurposeCodeSigning = true;
                                if (oid.Equals(KeyPurposeID.IdKPEmailProtection)) viewModel.PurposeEMailProtection = true;
                                if (oid.Equals(KeyPurposeID.IdKPIpsecEndSystem)) viewModel.PurposeIPsecEndSystem = true;
                                if (oid.Equals(KeyPurposeID.IdKPIpsecTunnel)) viewModel.PurposeIPsecTunnel = true;
                                if (oid.Equals(KeyPurposeID.IdKPIpsecUser)) viewModel.PurposeIPsecUser = true;
                                if (oid.Equals(KeyPurposeID.IdKPTimeStamping)) viewModel.PurposeTimeStamping = true;
                                if (oid.Equals(KeyPurposeID.IdKPOcspSigning)) viewModel.PurposeOCSPSigning = true;
                                if (oid.Equals(KeyPurposeID.IdKPSmartCardLogon)) viewModel.PurposeSmartCardLogon = true;
                                if (oid.Equals(KeyPurposeID.IdKPMacAddress)) viewModel.PurposeMACAddress = true;
                            }
                        }
                    }
                    catch
                    {
                        // Fallback to CSR parsing logic if cert parsing fails
                        PopulateFromCSR(csr, viewModel);
                    }
                }
                else
                {
                    // No signed cert, use CSR parsing logic
                    PopulateFromCSR(csr, viewModel);
                }

                return View(viewModel);
            }
        }
        return View(new CreateCSRViewModel());
    }

    // POST: CSR/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(CreateCSRViewModel model)
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