namespace DAL.Models;
public class SignedCSR
{
    public Guid Id { get; set; }

    public Guid OriginalRequestId { get; set; }

    public DateTime SignedOn { get; set; }

    public byte[] Certificate { get; set; }

    public DateTime NotBefore { get; set; }

    public DateTime NotAfter { get; set; }

    public bool IsValid => DateTime.Now >= NotBefore && DateTime.Now <= NotAfter;

    public SignedCSR() { }

    public SignedCSR(Guid originalRequestId
                     , DateTime signedOn
                     , byte[] certificate
                     , DateTime notBefore
                     , DateTime notAfter)
    {
        OriginalRequestId = originalRequestId;
        SignedOn = signedOn;
        Certificate = certificate;
        NotBefore = notBefore;
        NotAfter = notAfter;
    }

    public SignedCSR(Guid id
                     , Guid originalRequestId
                     , DateTime signedOn
                     , byte[] certificate
                     , DateTime notBefore
                     , DateTime notAfter)
        : this(originalRequestId, signedOn, certificate, notBefore, notAfter)
    {
        Id = id;
    }
}
