using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace PKI.API.Models;

/// <summary>
/// Čuva poslednji izdati CrlNumber (RFC 5280 CRL Number ekstenzija), kako bi se
/// pri svakoj generaciji CRL liste vrednost inkrementirala umesto da ostane fiksna.
/// Kolekcija sadrži tačno jedan dokument (identifikovan poljem Scope).
/// </summary>
public class CrlMetadataRecord
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string Scope { get; set; } = "IntermediateCA";
    public long LastCrlNumber { get; set; }
    public DateTime UpdatedAt { get; set; }
}
