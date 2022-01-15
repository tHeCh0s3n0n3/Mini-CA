using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using Common;
using System.ComponentModel.DataAnnotations.Schema;

namespace DAL.Models;
public class CSR
{
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid Id { get; set; }

    [Required]
    [Display(Name ="Country Code")]
    public string CountryCode { get; set; }

    [Required]
    [Display(Name = "Organization")]
    public string Organization { get; set; }

    [Display(Name = "Department")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string OrganizationUnitName { get; set; }

    [Required]
    [Display(Name = "Common Name")]
    public string CommonName { get; set; }

    [NotMapped]
    [Display(Name = "Alternate Names")]
    public List<string> AlternateNamesList
    {
        get
        {
            if (string.IsNullOrEmpty(AlternateNames))
            {
                return new List<string>();
            }
            else
            {
                return AlternateNames.Split('|').ToList();
            }
        }
        set
        {
            AlternateNames = string.Join('|', value);
        }
    }

    public string AlternateNames { get; set; }

    [Required]
    [Display(Name = "City")]
    public string Locality { get; set; }

    [Display(Name = "State/Province")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string State { get; set; }

    [Required]
    [Display(Name = "E-Mail Address")]
    public string EMailAddress { get; set; }

    [Required]
    public byte[] FileContents { get; set; }

    [Required]
    [Display(Name = "Filename")]
    public string FileName { get; set; }

    [Display(Name = "File Size")]
    public string FileSize
        => FileContents.LongLength.GetReadableBytes();

    public bool IsSigned { get; set; }

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
        PropertyInfo propertyInfo = this.GetType().GetProperty(propertyName);
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
