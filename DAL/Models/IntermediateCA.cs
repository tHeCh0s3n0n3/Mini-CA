#nullable enable
using System;
using System.ComponentModel.DataAnnotations;
using System.Reflection;

namespace DAL.Models;

[StronglyTypedId]
public partial struct IntermediateCAId { }

public class IntermediateCA
{
    public IntermediateCAId Id { get; set; } = new IntermediateCAId(Guid.NewGuid());

    [Required]
    [Display(Name = "Country Code")]
    [StringLength(2, MinimumLength = 2)]
    public string CountryCode { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Organization")]
    public string Organization { get; set; } = string.Empty;

    [Display(Name = "Department (OU)")]
    public string? OrganizationUnitName { get; set; }

    [Required]
    [Display(Name = "Common Name")]
    public string CommonName { get; set; } = string.Empty;

    [Display(Name = "City (Locality)")]
    public string? Locality { get; set; }

    [Display(Name = "State/Province")]
    public string? State { get; set; }

    [Required]
    [EmailAddress]
    [Display(Name = "E-Mail Address")]
    public string EMailAddress { get; set; } = string.Empty;

    [Required]
    public byte[] CsrFileContents { get; set; } = Array.Empty<byte>();

    [Required]
    [Display(Name = "Filename")]
    public string FileName { get; set; } = string.Empty;

    public byte[]? Certificate { get; set; }

    public string? EncryptedPrivateKey { get; set; }

    public bool IsSigned { get; set; }

    public DateTime SubmittedOn { get; set; }

    public DateTime? SignedOn { get; set; }

    public DateTime? NotBefore { get; set; }

    public DateTime? NotAfter { get; set; }

    public void SetProperty(string propertyName, string value)
    {
        PropertyInfo? propertyInfo = this.GetType().GetProperty(propertyName);
        if (null != propertyInfo && propertyInfo.CanWrite)
        {
            propertyInfo.SetValue(this, value);
        }
    }
}
