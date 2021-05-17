using Frontend.Models;
using Microsoft.AspNetCore.Mvc;
using Models.CSR;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.IO;

namespace Frontend.Controllers
{
    public class CSRController : Controller
    {
        public IActionResult Index()
        {
            return View(new UploadFileModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Upload(UploadFileModel uploadFile)
        {
            if (null == uploadFile || !ModelState.IsValid)
            {
                return RedirectToAction("Index");
            }

            CSR parsedCSR = new();

            if (uploadFile.FormFile.Length > 0)
            {
                using StreamReader sr = new(uploadFile.FormFile.OpenReadStream());
                PemReader csrReader = new(sr);
                Pkcs10CertificationRequest csr
                    = csrReader.ReadObject() as Pkcs10CertificationRequest;
                CertificationRequestInfo csrInfo = csr.GetCertificationRequestInfo();

                foreach (var item in CSR.ObjectIdentifiers)
                {
                    var valueResult = csrInfo.Subject.GetValueList(item.Key);
                    if (valueResult.Count == 1)
                    {
                        parsedCSR.SetProperty(item.Value, valueResult[0].ToString());
                    }
                }
            }

            return View(parsedCSR);
        }
    }
}
