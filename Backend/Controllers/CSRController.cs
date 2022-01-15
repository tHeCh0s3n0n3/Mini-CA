using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using DAL;
using DAL.Models;
using Backend.Models;
using Microsoft.Extensions.Options;
using System.Text;

namespace Backend.Controllers;
public class CSRController : Controller
{
    private readonly DB _db;
    private readonly CACertSettings _caCertSettings;

    public CSRController(DB db, IOptions<CACertSettings> caCertSettings)
    {
        _db = db;
        _caCertSettings = caCertSettings.Value;
    }

    // GET: CSR
    public async Task<IActionResult> Index()
    {
        var csrs = await _db.CSRs.ToListAsync();
        var model = new List<CSRIndexViewModel>();
        foreach(var csr in csrs)
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
        if (id is null)
        {
            return NotFound();
        }

        var csr = await _db.CSRs
            .FirstOrDefaultAsync(m => m.Id.Equals(id));
        var signedCSR = await _db.SignedCSRs
                .FirstOrDefaultAsync(m => m.OriginalRequestId.Equals(id));
        return csr is null
               ? NotFound()
#pragma warning disable CS8604 // Possible null reference argument.
               : View(new CSRDetailViewModel(csr, signedCSR));
#pragma warning restore CS8604 // Possible null reference argument.
    }

    // GET: CSR/Delete/5
    public async Task<IActionResult> Delete(Guid? id)
    {
        if (id is null)
        {
            return NotFound();
        }

        var csr = await _db.CSRs
            .FirstOrDefaultAsync(m => m.Id.Equals(id));
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
        var csr = await _db.CSRs.FindAsync(id);
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
        if (id is null)
        {
            return NotFound();
        }

        var csr = await _db.CSRs
            .FirstOrDefaultAsync(m => m.Id.Equals(id));

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

        var dbCSR = await _db.CSRs.FindAsync(processViewModel.OriginalRequestId);
        if (dbCSR is not null)
        {
            // Get the certificates
            var keyUsages = processViewModel.RequestedKeyUsages;
            var keyPurposeIDs = processViewModel.RequestedKeyPurposes;

            // Read the CSR
            Console.WriteLine("Reading the CSR...");
            var csr = Common.Certificate.ImportCSR(dbCSR.FileContents);

            // Grab the CA cert and its key
            var caCert = Common.Certificate.ImportCACert(_caCertSettings.CertFilePath);
            var caKey = Common.Certificate.ImportCAKey(_caCertSettings.CertKeyFilePath
                                                       , _caCertSettings.CertKeyPasswordFilePath);

            // Sign the cert
            Console.WriteLine("Signing the CSR...");
            var signedCert = Common.Certificate.SignCSR(csr, caCert, caKey, 1, keyUsages, keyPurposeIDs);
            var newCertFileContents = Common.Certificate.CertToFile(signedCert);

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
        var signedCSR = await _db.SignedCSRs.FindAsync(Id);

        if (signedCSR is null)
        {
            return NotFound();
        }

        var origCSR = await _db.CSRs.FindAsync(signedCSR.OriginalRequestId);
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

    private bool CSRExists(Guid id)
    {
        return _db.CSRs.Any(e => e.Id.Equals(id));
    }
}