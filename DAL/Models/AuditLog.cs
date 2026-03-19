using System.ComponentModel.DataAnnotations;

namespace DAL.Models;

[StronglyTypedId]
public partial struct AuditLogId { }

public class AuditLog
{
    public AuditLogId Id { get; set; } = new AuditLogId(Guid.NewGuid());

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [Required]
    public string Actor { get; set; }

    [Required]
    public string Action { get; set; }

    [Required]
    public string Subject { get; set; }

    public string Details { get; set; }
}
