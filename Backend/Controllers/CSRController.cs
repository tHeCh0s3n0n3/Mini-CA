using Backend.Filters;
using Backend.Models;
using DAL;
using DAL.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;

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
        List<CSRIndexViewModel> model = new();
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
            Org.BouncyCastle.X509.X509Certificate signedCert = Common.Certificate.SignCSR(csr, caCert, caKey, 1, keyUsages, keyPurposeIDs);
            string newCertFileContents = Common.Certificate.CertToFile(signedCert);

            // Save signed cert
            SignedCSR signedCSR = new(dbCSR.Id
                                      , DateTime.Now
                                      , Encoding.UTF8.GetBytes(newCertFileContents)
                                      , DateTime.Now
                                      , processViewModel.ExpieryDate);
            dbCSR.IsSigned = true;

            _db.CSRs.Update(dbCSR);
            _db.SignedCSRs.Add(signedCSR);
            await _db.SaveChangesAsync();
        }

        return RedirectToAction(nameof(Index));
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