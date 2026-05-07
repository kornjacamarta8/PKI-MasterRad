using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace PKI.API.Models;

public class CertificateRecord
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string SerialNumber { get; set; } = null!;
    public string SubjectName { get; set; } = null!;
    public string IssuerName { get; set; } = null!;
    public string CertificateType { get; set; } = null!; // RootCA, IntermediateCA, EndEntity
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Status { get; set; } = "Active"; // Active, Revoked, Expired
    public string? RevocationReason { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string PemCertificate { get; set; } = null!;
    public string? IssuedBySerial { get; set; } // serial broj CA koji je izdao
    public string? PrivateKeyPem { get; set; }
}