using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace PKI.API.Models;

public class CaKeyRecord
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string CaType { get; set; } = null!; // RootCA, IntermediateCA
    public string EncryptedPrivateKey { get; set; } = null!;
    public string PublicKeyCertificatePem { get; set; } = null!;
    public DateTime CreatedAt { get; set; }
}