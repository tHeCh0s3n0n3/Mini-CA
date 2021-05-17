using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Reflection;

namespace Models.CSR
{
    public class CSR
    {
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

        [Required]
        [Display(Name = "City")]
        public string Locality { get; set; }

        [Display(Name = "State/Province")]
        [DisplayFormat(NullDisplayText = "-- not specified --")]
        public string State { get; set; }

        [Required]
        [Display(Name = "E-Mail Address")]
        public string EMailAddress { get; set; }

        public void SetProperty(string propertyName, string value)
        {
            PropertyInfo propertyInfo = this.GetType().GetProperty(propertyName);
            if(null != propertyInfo && propertyInfo.CanWrite)
            {
                propertyInfo.SetValue(this, value);
            }
        }
    }
}
