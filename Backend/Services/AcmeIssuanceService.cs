using DAL;
using DAL.Models;
using Common;
using Microsoft.Extensions.Options;
using Backend.Models;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;

namespace Backend.Services;

public class AcmeIssuanceService : IIssueCertificates
{
    private readonly DB _db;
    private readonly CACertSettings _caCertSettings;

    public AcmeIssuanceService(DB db, IOptions<CACertSettings> caCertSettings)
    {
        _db = db;
        _caCertSettings = caCertSettings.Value;
    }

    public async Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(string csr, IEnumerable<Identifier> identifiers, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Import the CSR using BouncyCastle
            var csrBytes = Encoding.UTF8.GetBytes(csr);
            var bcCsr = Common.Certificate.ImportCSR(csrBytes);

            // 2. Grab the CA cert and its key
            var caCert = Common.Certificate.ImportCACert(_caCertSettings.CertFilePath);
            var caKey = Common.Certificate.ImportCAKey(_caCertSettings.CertKeyFilePath, _caCertSettings.CertKeyPasswordFilePath);

            // 3. Default ACME usage: Digital Signature, Key Encipherment, Server Auth
            var keyUsages = new List<int> { 
                Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature, 
                Org.BouncyCastle.Asn1.X509.KeyUsage.KeyEncipherment 
            };
            var keyPurposes = new List<Org.BouncyCastle.Asn1.X509.KeyPurposeID> { 
                Org.BouncyCastle.Asn1.X509.KeyPurposeID.IdKPServerAuth 
            };

            // 4. Sign the cert
            var signedCert = Common.Certificate.SignCSR(bcCsr, caCert, caKey, 1, keyUsages, keyPurposes);
            
            // 5. Audit Log
            var audit = new AuditLog
            {
                Actor = "ACME",
                Action = "ACME Sign",
                Subject = bcCsr.GetCertificationRequestInfo().Subject.ToString(),
                Timestamp = DateTime.UtcNow,
                Details = $"Identifiers: {string.Join(", ", identifiers.Select(i => i.Value))}"
            };
            _db.AuditLogs.Add(audit);
            await _db.SaveChangesAsync(cancellationToken);

            return (signedCert.GetEncoded(), null);
        }
        catch (Exception ex)
        {
            return (null, new AcmeError("urn:ietf:params:acme:error:serverInternal", ex.Message, null, null));
        }
    }
}
