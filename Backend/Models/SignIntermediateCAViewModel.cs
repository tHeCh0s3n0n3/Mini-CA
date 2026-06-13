#nullable enable
using System;
using System.ComponentModel.DataAnnotations;

namespace Backend.Models;

public class SignIntermediateCAViewModel
{
    public Guid Id { get; set; }

    [Display(Name = "Country Code")]
    public string CountryCode { get; set; } = string.Empty;

    [Display(Name = "Organization")]
    public string Organization { get; set; } = string.Empty;

    [Display(Name = "Department (OU)")]
    public string OrganizationUnitName { get; set; } = string.Empty;

    [Display(Name = "Common Name")]
    public string CommonName { get; set; } = string.Empty;

    [Display(Name = "City")]
    public string Locality { get; set; } = string.Empty;

    [Display(Name = "State")]
    public string State { get; set; } = string.Empty;

    [Display(Name = "E-Mail Address")]
    public string EMailAddress { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Date)]
    [Display(Name = "Expiry Date")]
    public DateTime ExpieryDate { get; set; }

    public DateTime MaxExpiryDate { get; set; }
}
