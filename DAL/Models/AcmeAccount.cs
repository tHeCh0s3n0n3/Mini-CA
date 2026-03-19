using System.ComponentModel.DataAnnotations;

namespace DAL.Models;

[StronglyTypedId]
public partial struct AcmeAccountId { }

public class AcmeAccount
{
    public AcmeAccountId Id { get; set; } = new AcmeAccountId(Guid.NewGuid());

    [Required]
    public string AccountKey { get; set; }

    public AcmeEabId? EabId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsDeactivated { get; set; } = false;
}
