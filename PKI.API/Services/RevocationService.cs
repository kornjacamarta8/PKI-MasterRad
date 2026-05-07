using MongoDB.Driver;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PKI.API.Models;

namespace PKI.API.Services;

public class RevocationService
{
    private readonly MongoDbService _mongo;
    private readonly CertificateAuthorityService _caService;

    public RevocationService(MongoDbService mongo, CertificateAuthorityService caService)
    {
        _mongo = mongo;
        _caService = caService;
    }

    public bool RevokeCertificate(string serialNumber, string reason)
    {
        var cert = _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Eq(c => c.SerialNumber, serialNumber))
            .FirstOrDefault();

        if (cert == null || cert.Status == "Revoked")
            return false;

        var update = Builders<CertificateRecord>.Update
            .Set(c => c.Status, "Revoked")
            .Set(c => c.RevocationReason, reason)
            .Set(c => c.RevokedAt, DateTime.UtcNow);

        _mongo.Certificates.UpdateOne(
            Builders<CertificateRecord>.Filter.Eq(c => c.SerialNumber, serialNumber),
            update);
        return true;
    }

    public string GenerateCRL()
    {
        if (_caService.IntermediateCertificate == null || _caService.IntermediateKeyPair == null)
            throw new InvalidOperationException("Intermediate CA nije inicijalizovan.");

        var revokedCerts = _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Eq(c => c.Status, "Revoked"))
            .ToList();

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(_caService.IntermediateCertificate.SubjectDN);
        crlGen.SetThisUpdate(DateTime.UtcNow);
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(7));

        foreach (var cert in revokedCerts)
        {
            crlGen.AddCrlEntry(
                new BigInteger(cert.SerialNumber),
                cert.RevokedAt ?? DateTime.UtcNow,
                GetReasonCode(cert.RevocationReason));
        }

        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    _caService.IntermediateCertificate.GetPublicKey())));
        crlGen.AddExtension(X509Extensions.CrlNumber, false,
            new CrlNumber(BigInteger.One));

        var signer = new Asn1SignatureFactory("SHA256WithRSAEncryption",
            _caService.IntermediateKeyPair.Private, new SecureRandom());

        var crl = crlGen.Generate(signer);

        using var sw = new StringWriter();
        var writer = new PemWriter(sw);
        writer.WriteObject(crl);
        return sw.ToString();
    }

    private int GetReasonCode(string? reason) => reason switch
    {
        "KeyCompromise" => Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise,
        "CACompromise" => Org.BouncyCastle.Asn1.X509.CrlReason.CACompromise,
        "AffiliationChanged" => Org.BouncyCastle.Asn1.X509.CrlReason.AffiliationChanged,
        "Superseded" => Org.BouncyCastle.Asn1.X509.CrlReason.Superseded,
        "CessationOfOperation" => Org.BouncyCastle.Asn1.X509.CrlReason.CessationOfOperation,
        _ => Org.BouncyCastle.Asn1.X509.CrlReason.Unspecified
    };
}