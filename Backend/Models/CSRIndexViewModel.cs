using Common;
using DAL.Models;
using System.ComponentModel.DataAnnotations;

namespace Backend.Models;
public class CSRIndexViewModel
{
    public CSRId Id { get; set; }

    [Required]
    [Display(Name = "Country Code")]
    public string CountryCode { get; set; }

    [Required]
    [Display(Name = "Common Name")]
    public string CommonName { get; set; }

    [Required]
    [Display(Name = "Filename")]
    public string FileName { get; set; }

    [Display(Name = "File Size")]
    public string FileSize { get; set; }

    public bool IsSigned { get; set; }

    [Display(Name = "Submitted On")]
    [DataType(DataType.Date)]
    public DateTime SubmittedOn { get; set; }

    public SignedCSRId? SignedCSRId { get; set; }

    public CSRIndexViewModel(CSR csr, SignedCSR? signedCSR)
    {
        Id = csr.Id;
        CountryCode = csr.CountryCode;
        CommonName = csr.CommonName;
        FileName = csr.FileName;
        IsSigned = csr.IsSigned;
        SubmittedOn = csr.SubmittedOn;
        FileSize = csr.FileContents.LongLength.GetReadableBytes();
        SignedCSRId = (IsSigned
                       && signedCSR is not null
                       ?    signedCSR.Id
                       : null);
    }
}