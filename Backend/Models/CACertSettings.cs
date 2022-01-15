namespace Backend.Models;
public class CACertSettings
{
    public string CertFilePath { get; set; }
    public string CertKeyFilePath { get; set; }
    public string CertKeyPasswordFilePath { get; set; }

    public CACertSettings()
    {
        CertFilePath = string.Empty;
        CertKeyFilePath = string.Empty;
        CertKeyPasswordFilePath = string.Empty;
    }
}