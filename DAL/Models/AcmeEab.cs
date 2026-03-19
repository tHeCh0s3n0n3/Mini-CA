using System.ComponentModel.DataAnnotations;

namespace DAL.Models;

[StronglyTypedId]
public partial struct AcmeEabId { }

public class AcmeEab
{
    public AcmeEabId Id { get; set; } = new AcmeEabId(Guid.NewGuid());

    [Required]
    public string KID { get; set; }

    [Required]
    public string EncryptedHmacKey { get; set; }

    public string Description { get; set; }

    public string AllowedIdentifierPattern { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastUsedAt { get; set; }

    public int UsageCount { get; set; } = 0;
}
