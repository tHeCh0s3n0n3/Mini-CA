#nullable enable
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System.Linq;

namespace DAL.Models;

public class UploadFileModel
{
    [Required]
    [Display(Name = "CSR File")]
    public IFormFile? FormFile { get; set; }
}

public class SanItem
{
    public int Type { get; set; }
    public string Value { get; set; } = string.Empty;
}

public class CreateCSRViewModel
{
    [Required]
    [Display(Name = "Country Code (e.g. US, AE)")]
    [StringLength(2, MinimumLength = 2)]
    public string CountryCode { get; set; } = "AE";

    [Required]
    [Display(Name = "Organization")]
    public string Organization { get; set; } = string.Empty;

    [Display(Name = "Department (OU)")]
    public string? OrganizationUnitName { get; set; }

    [Required]
    [Display(Name = "Common Name (FQDN)")]
    public string CommonName { get; set; } = string.Empty;

    [Display(Name = "City (Locality)")]
    public string? Locality { get; set; }

    [Display(Name = "State/Province")]
    public string? State { get; set; }

    [Required]
    [EmailAddress]
    [Display(Name = "E-Mail Address")]
    public string EMailAddress { get; set; } = string.Empty;

    public List<SanItem> AlternateNames { get; set; } = [];

    /* Purposes */
    [Display(Name = "All Purposes")]
    public bool PurposeAll { get; set; }

    [Display(Name = "Server Authentication")]
    public bool PurposeServerAuth { get; set; } = true;

    [Display(Name = "Client Authentication")]
    public bool PurposeClientAuth { get; set; }

    [Display(Name = "Code Signing")]
    public bool PurposeCodeSigning { get; set; }

    [Display(Name = "E-Mail Protection")]
    public bool PurposeEMailProtection { get; set; }

    [Display(Name = "IPsec End System")]
    public bool PurposeIPsecEndSystem { get; set; }

    [Display(Name = "IPsec Tunnel")]
    public bool PurposeIPsecTunnel { get; set; }

    [Display(Name = "IPsec User")]
    public bool PurposeIPsecUser { get; set; }

    [Display(Name = "Time Stamping")]
    public bool PurposeTimeStamping { get; set; }

    [Display(Name = "OCSP Signing")]
    public bool PurposeOCSPSigning { get; set; }

    [Display(Name = "Smart Card Log-on")]
    public bool PurposeSmartCardLogon { get; set; }

    [Display(Name = "MAC Address")]
    public bool PurposeMACAddress { get; set; }

    /* Key Usages */
    [Display(Name = "All Usages")]
    public bool UsageAll { get; set; }

    [Display(Name = "Digital Signing")]
    public bool UsageDigitalSignature { get; set; } = true;

    [Display(Name = "Non Repudiation", Description = "a.k.a. Content Commitment")]
    public bool UsageNonRepudiation { get; set; }

    [Display(Name = "Key Encipherment")]
    public bool UsageKeyEncipherment { get; set; } = true;

    [Display(Name = "Data Encipherment")]
    public bool UsageDataEncipherment { get; set; }

    [Display(Name = "Key Agreement")]
    public bool UsageKeyAgreement { get; set; }

    [Display(Name = "Key Certificate Signing")]
    public bool UsageKeyCertSigning { get; set; }

    [Display(Name = "CRL Signing", Description = "Signing of Certificate Revocation Lists (CRLs)")]
    public bool UsageCRLSigning { get; set; }

    [Display(Name = "Encipherment Only")]
    public bool UsageEncipherOnly { get; set; }

    [Display(Name = "Decipherment Only")]
    public bool UsageDecipherOnly { get; set; }

    public List<KeyPurposeID> RequestedKeyPurposes
    {
        get
        {
            List<KeyPurposeID> retval = [];
            if (PurposeAll) retval.Add(KeyPurposeID.AnyExtendedKeyUsage);
            if (PurposeServerAuth) retval.Add(KeyPurposeID.IdKPServerAuth);
            if (PurposeClientAuth) retval.Add(KeyPurposeID.IdKPClientAuth);
            if (PurposeCodeSigning) retval.Add(KeyPurposeID.IdKPCodeSigning);
            if (PurposeEMailProtection) retval.Add(KeyPurposeID.IdKPEmailProtection);
            if (PurposeIPsecEndSystem) retval.Add(KeyPurposeID.IdKPIpsecEndSystem);
            if (PurposeIPsecTunnel) retval.Add(KeyPurposeID.IdKPIpsecTunnel);
            if (PurposeIPsecUser) retval.Add(KeyPurposeID.IdKPIpsecUser);
            if (PurposeTimeStamping) retval.Add(KeyPurposeID.IdKPTimeStamping);
            if (PurposeOCSPSigning) retval.Add(KeyPurposeID.IdKPOcspSigning);
            if (PurposeSmartCardLogon) retval.Add(KeyPurposeID.IdKPSmartCardLogon);
            if (PurposeMACAddress) retval.Add(KeyPurposeID.IdKPMacAddress);
            return retval;
        }
    }

    public List<int> RequestedKeyUsages
    {
        get
        {
            List<int> retval = [];
            if (UsageDigitalSignature) retval.Add(KeyUsage.DigitalSignature);
            if (UsageNonRepudiation) retval.Add(KeyUsage.NonRepudiation);
            if (UsageKeyEncipherment) retval.Add(KeyUsage.KeyEncipherment);
            if (UsageDataEncipherment) retval.Add(KeyUsage.DataEncipherment);
            if (UsageKeyAgreement) retval.Add(KeyUsage.KeyAgreement);
            if (UsageKeyCertSigning) retval.Add(KeyUsage.KeyCertSign);
            if (UsageCRLSigning) retval.Add(KeyUsage.CrlSign);
            if (UsageEncipherOnly) retval.Add(KeyUsage.EncipherOnly);
            if (UsageDecipherOnly) retval.Add(KeyUsage.DecipherOnly);
            return retval;
        }
    }
}

public class CSRGeneratedSuccessViewModel
{
    public CSR CSR { get; set; } = null!;
    public string PrivateKeyPem { get; set; } = string.Empty;
}
