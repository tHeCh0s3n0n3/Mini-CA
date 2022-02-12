using Common;
using DAL.Models;
using System.ComponentModel.DataAnnotations;

namespace Backend.Models;
public class CSRDetailViewModel
{
    public CSRId? OriginalRequestId { get; set; }

    [Display(Name = "Country Code")]
    public string? CountryCode { get; private set; }
 
    [Display(Name = "Organization")]
    public string? Organization { get; private set; }

    [Display(Name = "Department")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string? OrganizationUnitName { get; private set; }

    [Display(Name = "Common Name")]
    public string? CommonName { get; private set; }

    [Display(Name = "Alternate Names")]
    public List<string> AlternateNames { get; private set; } = new List<string>();

    [Display(Name = "City")]
    public string? Locality { get; private set; }

    [Display(Name = "State/Province")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string? State { get; private set; }

    [Display(Name = "E-Mail Address")]
    public string? EMailAddress { get; private set; }

    [Display(Name = "Filename")]
    public string? FileName { get; private set; }

    [Display(Name = "File Size")]
    public string? FileSize { get; private set; }

    [Display(Name = "Is Signed")]
    public bool? IsSigned { get; private set; }

    [Display(Name = "Submitted On")]
    public DateTime? SubmittedOn { get; private set; }

    /** Signed CSR Properties **/
    public SignedCSRId? Id { get; set; }

    [Display(Name = "Signed On")]
    public DateTime? SignedOn { get; set; }

    public byte[]? Certificate { get; set; }

    [Display(Name = "Not Before")]
    public DateTime? NotBefore { get; set; }

    [Display(Name = "Not After")]
    public DateTime? NotAfter { get; set; }

    [Display(Name = "Is Valid")]
    public bool IsValid => DateTime.Now >= NotBefore && DateTime.Now <= NotAfter;

    public CSRDetailViewModel() { }

    public CSRDetailViewModel(CSR csr, SignedCSR signedCSR)
    {
        OriginalRequestId = csr.Id;
        CountryCode = csr.CountryCode;
        Organization = csr.Organization;
        OrganizationUnitName = csr.OrganizationUnitName;
        CommonName = csr.CommonName;
        AlternateNames = csr.AlternateNamesList;
        Locality = csr.Locality;
        State = csr.State;
        EMailAddress = csr.EMailAddress;
        FileName = csr.FileName;
        IsSigned = csr.IsSigned;
        SubmittedOn = csr.SubmittedOn;
        FileSize = csr.FileContents.LongLength.GetReadableBytes();

        if (signedCSR is not null)
        {
            Id = signedCSR.Id;
            SignedOn = signedCSR.SignedOn;
            Certificate = signedCSR.Certificate;
            NotBefore = signedCSR.NotBefore;
            NotAfter = signedCSR.NotAfter;
        }
    }
}
