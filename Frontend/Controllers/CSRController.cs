using Frontend.Models;
using Microsoft.AspNetCore.Mvc;
using DAL.Models;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Serilog;

namespace Frontend.Controllers
{
    public class CSRController : Controller
    {
        private readonly DAL.DB _db;

        public CSRController(DAL.DB db)
        {
            Log.Information("Entered CSRController");
            _db = db;
        }

        public IActionResult Index()
        {
            Log.Information("Showing CSR Index page.");
            return View(new UploadFileModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upload(UploadFileModel uploadFile)
        {
            Log.Information("Started upload function");

            try
            {
                if (null == uploadFile || !ModelState.IsValid)
                {
                    return RedirectToAction("Index");
                }

                CSR parsedCSR = new();

                if (uploadFile.FormFile.Length > 0)
                {
                    parsedCSR.FileName = uploadFile.FormFile.FileName;
                    parsedCSR.IsSigned = false;
                    parsedCSR.SubmittedOn = DateTime.Now;

                    using Stream s = uploadFile.FormFile.OpenReadStream();
                    using (MemoryStream ms = new())
                    {
                        await s.CopyToAsync(ms);
                        parsedCSR.FileContents = ms.ToArray();
                    }

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

                    foreach (var item in CSR.ObjectIdentifiers)
                    {
                        var valueResult = csrInfo.Subject.GetValueList(item.Key);
                        if (valueResult.Count == 1)
                        {
                            if (valueResult[0] is null)
                            {
                                continue;
                            }
                            parsedCSR.SetProperty(item.Value, $"{valueResult[0]}");
                        }
                    }

                    List<string> alternateNames = Common.Certificate.GetSANs(csr).ToList();
                    parsedCSR.AlternateNamesList = alternateNames;
                }
                await _db.Database.EnsureCreatedAsync();
                _db.Add<CSR>(parsedCSR);
                await _db.SaveChangesAsync();

                return View(parsedCSR);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
