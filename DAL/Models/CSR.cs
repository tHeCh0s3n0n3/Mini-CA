using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.ComponentModel.DataAnnotations.Schema;

#nullable enable

namespace DAL.Models;

[StronglyTypedId]
public partial struct CSRId { }

public class CSR
{
    public CSRId Id { get; set; } = new CSRId(Guid.NewGuid());

    [Required]
    [Display(Name ="Country Code")]
    public string CountryCode { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Organization")]
    public string Organization { get; set; } = string.Empty;

    [Display(Name = "Department")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string OrganizationUnitName { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Common Name")]
    public string CommonName { get; set; } = string.Empty;

    [NotMapped]
    [Display(Name = "Alternate Names")]
    public List<string> AlternateNamesList
    {
        get
        {
            if (string.IsNullOrEmpty(AlternateNames))
            {
                return [];
            }
            else
            {
                return AlternateNames.Split('|')
                                     .ToList();
            }
        }
        set
        {
            AlternateNames = string.Join('|', value);
        }
    }

    public string AlternateNames { get; set; } = string.Empty;

    [Required]
    [Display(Name = "City")]
    public string Locality { get; set; } = string.Empty;

    [Display(Name = "State/Province")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string State { get; set; } = string.Empty;

    [Required]
    [Display(Name = "E-Mail Address")]
    public string EMailAddress { get; set; } = string.Empty;

    [Required]
    public byte[] FileContents { get; set; } = Array.Empty<byte>();

    [Required]
    [Display(Name = "Filename")]
    public string FileName { get; set; } = string.Empty;

    [Display(Name = "File Size")]
    public string FileSize
        => FileContents.LongLength.GetReadableBytes();

    public bool IsSigned { get; set; }

    public string? UserId { get; set; }

    public DateTime SubmittedOn { get; set; }

    public static readonly Dictionary<DerObjectIdentifier, string> ObjectIdentifiers = new()
    {
        { X509Name.C, "CountryCode" }
        , { X509Name.O, "Organization" }
        , { X509Name.OU, "OrganizationUnitName" }
        , { X509Name.CN, "CommonName" }
        , { X509Name.L, "Locality" }
        , { X509Name.ST, "State" }
        , { X509Name.E, "EMailAddress" }
    };

    public void SetProperty(string propertyName, string value)
    {
        PropertyInfo? propertyInfo = this.GetType().GetProperty(propertyName);
        if(null != propertyInfo && propertyInfo.CanWrite)
        {
            propertyInfo.SetValue(this, value);
        }
    }

    public override string ToString()
    {
        return $"{CommonName}, {IsSigned}, {SubmittedOn:O}";
    }
}
