using DAL;
using DAL.Models;
using Common;
using Microsoft.Extensions.Options;
using Backend.Models;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;

namespace Backend.Services;

public class AcmeIssuanceService : IIssueCertificates
{
    private readonly DB _db;
    private readonly CACertSettings _caCertSettings;
    private readonly IAcmeContext _acmeContext;

    public AcmeIssuanceService(DB db, IOptions<CACertSettings> caCertSettings, IAcmeContext acmeContext)
    {
        _db = db;
        _caCertSettings = caCertSettings.Value;
        _acmeContext = acmeContext;
    }

    public async Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(string csr, IEnumerable<Identifier> identifiers, CancellationToken cancellationToken)
    {
        try
        {
            // 0. Enforce EAB Whitelisting if applicable
            var currentAccount = _acmeContext.CurrentAccount;
            if (currentAccount != null && Guid.TryParse(currentAccount.AccountId, out var accountId))
            {
                var dbAccount = await _db.AcmeAccounts
                    .FirstOrDefaultAsync(a => a.Id == new AcmeAccountId(accountId), cancellationToken);

                if (dbAccount?.EabId != null)
                {
                    var eab = await _db.AcmeEabs.FindAsync(new object[] { dbAccount.EabId.Value }, cancellationToken);
                    if (eab != null)
                    {
                        // Check whitelisting
                        if (!string.IsNullOrEmpty(eab.AllowedIdentifierPattern))
                        {
                            var regex = new Regex(eab.AllowedIdentifierPattern, RegexOptions.IgnoreCase);
                            foreach (var id in identifiers)
                            {
                                if (!regex.IsMatch(id.Value))
                                {
                                    return (null, new AcmeError("urn:ietf:params:acme:error:unauthorized", $"Identifier '{id.Value}' is not allowed for this ACME account.", null, null));
                                }
                            }
                        }

                        // Update metadata
                        eab.LastUsedAt = DateTime.UtcNow;
                        eab.UsageCount++;
                        await _db.SaveChangesAsync(cancellationToken);
                    }
                }
            }

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
                Actor = $"ACME ({currentAccount?.AccountId ?? "Unknown"})",
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
