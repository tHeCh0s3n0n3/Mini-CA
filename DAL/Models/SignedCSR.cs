namespace DAL.Models;

[StronglyTypedId]
public partial struct SignedCSRId { }

public class SignedCSR
{
    public SignedCSRId Id { get; set; }

    public CSRId OriginalRequestId { get; set; }

    public DateTime SignedOn { get; set; }

    public byte[] Certificate { get; set; }

    public DateTime NotBefore { get; set; }

    public DateTime NotAfter { get; set; }

    public bool IsValid => DateTime.Now >= NotBefore && DateTime.Now <= NotAfter;

    public SignedCSR() { }

    public SignedCSR(CSRId originalRequestId
                     , DateTime signedOn
                     , byte[] certificate
                     , DateTime notBefore
                     , DateTime notAfter)
    {
        Id = new SignedCSRId(Guid.NewGuid());
        OriginalRequestId = originalRequestId;
        SignedOn = signedOn;
        Certificate = certificate;
        NotBefore = notBefore;
        NotAfter = notAfter;
    }

    public SignedCSR(SignedCSRId id
                     , CSRId originalRequestId
                     , DateTime signedOn
                     , byte[] certificate
                     , DateTime notBefore
                     , DateTime notAfter)
        : this(originalRequestId, signedOn, certificate, notBefore, notAfter)
    {
        Id = id;
    }
}
