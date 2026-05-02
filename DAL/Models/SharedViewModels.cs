#nullable enable
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

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
    [Display(Name = "Server Authentication")]
    public bool PurposeServerAuth { get; set; } = true;

    [Display(Name = "Client Authentication")]
    public bool PurposeClientAuth { get; set; }

    [Display(Name = "Code Signing")]
    public bool PurposeCodeSigning { get; set; }

    [Display(Name = "E-Mail Protection")]
    public bool PurposeEMailProtection { get; set; }

    /* Key Usages */
    [Display(Name = "Digital Signing")]
    public bool UsageDigitalSignature { get; set; } = true;

    [Display(Name = "Key Encipherment")]
    public bool UsageKeyEncipherment { get; set; } = true;

    public List<KeyPurposeID> RequestedKeyPurposes
    {
        get
        {
            List<KeyPurposeID> retval = [];
            if (PurposeServerAuth) retval.Add(KeyPurposeID.IdKPServerAuth);
            if (PurposeClientAuth) retval.Add(KeyPurposeID.IdKPClientAuth);
            if (PurposeCodeSigning) retval.Add(KeyPurposeID.IdKPCodeSigning);
            if (PurposeEMailProtection) retval.Add(KeyPurposeID.IdKPEmailProtection);
            return retval;
        }
    }

    public List<int> RequestedKeyUsages
    {
        get
        {
            List<int> retval = [];
            if (UsageDigitalSignature) retval.Add(KeyUsage.DigitalSignature);
            if (UsageKeyEncipherment) retval.Add(KeyUsage.KeyEncipherment);
            return retval;
        }
    }
}

public class CSRGeneratedSuccessViewModel
{
    public CSR CSR { get; set; } = null!;
    public string PrivateKeyPem { get; set; } = string.Empty;
}
