using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace PKI.API.Models;

public class AuditLogRecord
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string Action { get; set; } = null!;
    // IssueCertificate, RevokeCertificate, VerifyCertificate, GenerateCRL, InitializeCA

    public string? SerialNumber { get; set; }
    public string? SubjectName { get; set; }
    public string? Details { get; set; }
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string IpAddress { get; set; } = null!;
}