using DAL.Models;

#nullable enable

namespace Frontend.Models;

public class UserDashboardViewModel
{
    public List<CSRItemViewModel> CSRs { get; set; } = new();
    public UploadFileModel UploadModel { get; set; } = new();
}

public class CSRItemViewModel
{
    public CSR CSR { get; set; }
    public SignedCSR? SignedCSR { get; set; }

    public CSRItemViewModel(CSR csr, SignedCSR? signedCsr)
    {
        CSR = csr;
        SignedCSR = signedCsr;
    }
}
