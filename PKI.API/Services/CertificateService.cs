using MongoDB.Driver;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;
using PKI.API.Models;

namespace PKI.API.Services;

public class CertificateService
{
    private readonly MongoDbService _mongo;
    private readonly CertificateAuthorityService _caService;

    public CertificateService(MongoDbService mongo, CertificateAuthorityService caService)
    {
        _mongo = mongo;
        _caService = caService;
    }

    public CertificateRecord IssueCertificate(string commonName, string organization,
        string country, int validityDays = 365)
    {
        if (_caService.IntermediateCertificate == null || _caService.IntermediateKeyPair == null)
            throw new InvalidOperationException("Intermediate CA nije inicijalizovan.");

        var keyPair = _caService.GenerateRsaKeyPair(2048);

        var gen = new X509V3CertificateGenerator();
        var serial = BigInteger.ProbablePrime(120, new Random());
        var subject = new X509Name($"CN={commonName}, O={organization}, C={country}");

        gen.SetSerialNumber(serial);
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(_caService.IntermediateCertificate.SubjectDN);
        gen.SetNotBefore(DateTime.UtcNow);
        gen.SetNotAfter(DateTime.UtcNow.AddDays(validityDays));
        gen.SetPublicKey(keyPair.Public);

        gen.AddExtension(X509Extensions.BasicConstraints, true,
            new BasicConstraints(false));
        gen.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
        gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
            new ExtendedKeyUsage(new KeyPurposeID[] {
                KeyPurposeID.id_kp_serverAuth,
                KeyPurposeID.id_kp_clientAuth
            }));
        gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));
        gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    _caService.IntermediateCertificate.GetPublicKey())));

        var signer = new Asn1SignatureFactory("SHA256WithRSAEncryption",
            _caService.IntermediateKeyPair.Private, new SecureRandom());
        var certificate = gen.Generate(signer);

        var record = new CertificateRecord
        {
            SerialNumber = serial.ToString(),
            SubjectName = subject.ToString(),
            IssuerName = _caService.IntermediateCertificate.SubjectDN.ToString(),
            CertificateType = "EndEntity",
            IssuedAt = certificate.NotBefore,
            ExpiresAt = certificate.NotAfter,
            Status = "Active",
            IssuedBySerial = _caService.IntermediateCertificate.SerialNumber.ToString(),
            PemCertificate = _caService.ConvertToPem(certificate),
            PrivateKeyPem = ConvertPrivateKeyToPem(keyPair)
        };

        _mongo.Certificates.InsertOne(record);
        return record;
    }

    public List<CertificateRecord> GetAll() =>
        _mongo.Certificates.Find(Builders<CertificateRecord>.Filter.Empty).ToList();

    public CertificateRecord? GetBySerial(string serial) =>
        _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Eq(c => c.SerialNumber, serial))
            .FirstOrDefault();

    public List<CertificateRecord> GetByStatus(string status) =>
        _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Eq(c => c.Status, status))
            .ToList();

    private string ConvertPrivateKeyToPem(Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair)
    {
        using var sw = new StringWriter();
        var writer = new PemWriter(sw);
        writer.WriteObject(keyPair.Private);
        return sw.ToString();
    }
}