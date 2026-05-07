using MongoDB.Driver;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using PKI.API.Models;

namespace PKI.API.Services;

public class CertificateAuthorityService
{
    private readonly MongoDbService _mongo;
    private readonly KeyEncryptionService _encryption;

    private AsymmetricCipherKeyPair? _rootKeyPair;
    private AsymmetricCipherKeyPair? _intermediateKeyPair;
    private Org.BouncyCastle.X509.X509Certificate? _rootCertificate;
    private Org.BouncyCastle.X509.X509Certificate? _intermediateCertificate;

    public Org.BouncyCastle.X509.X509Certificate? RootCertificate => _rootCertificate;
    public Org.BouncyCastle.X509.X509Certificate? IntermediateCertificate => _intermediateCertificate;
    public AsymmetricCipherKeyPair? IntermediateKeyPair => _intermediateKeyPair;

    public CertificateAuthorityService(MongoDbService mongo, KeyEncryptionService encryption)
    {
        _mongo = mongo;
        _encryption = encryption;
    }

    public void InitializeCA()
    {
        Console.WriteLine("Provjera postojeceg CA u bazi...");

        var existingKeys = _mongo.CaKeys
            .Find(Builders<CaKeyRecord>.Filter.Empty)
            .ToList();

        if (existingKeys.Count >= 2)
        {
            Console.WriteLine("CA pronadjen u bazi - ucitavanje postojecih kljuceva...");
            LoadCAFromMongo(existingKeys);
            Console.WriteLine("CA uspjesno ucitan iz baze.");
            return;
        }

        Console.WriteLine("CA ne postoji - generisanje novog...");
        _rootKeyPair = GenerateRsaKeyPair(4096);
        _rootCertificate = CreateRootCACertificate(_rootKeyPair);

        _intermediateKeyPair = GenerateRsaKeyPair(2048);
        _intermediateCertificate = CreateIntermediateCACertificate(
            _intermediateKeyPair, _rootCertificate, _rootKeyPair);

        SaveCAToMongo();
        Console.WriteLine("PKI infrastruktura uspjesno inicijalizovana i sacuvana.");
    }

    private void LoadCAFromMongo(List<CaKeyRecord> keys)
    {
        var rootKey = keys.First(k => k.CaType == "RootCA");
        var intermediateKey = keys.First(k => k.CaType == "IntermediateCA");

        _rootKeyPair = LoadKeyPairFromEncrypted(rootKey.EncryptedPrivateKey);
        _rootCertificate = LoadCertificateFromPem(rootKey.PublicKeyCertificatePem);

        _intermediateKeyPair = LoadKeyPairFromEncrypted(intermediateKey.EncryptedPrivateKey);
        _intermediateCertificate = LoadCertificateFromPem(intermediateKey.PublicKeyCertificatePem);
    }

    private AsymmetricCipherKeyPair LoadKeyPairFromEncrypted(string encryptedPem)
    {
        var decryptedPem = _encryption.Decrypt(encryptedPem);
        using var sr = new StringReader(decryptedPem);
        var reader = new PemReader(sr);
        var obj = reader.ReadObject();

        if (obj is AsymmetricCipherKeyPair keyPair)
            return keyPair;

        // Ako je samo privatni kljuc
        var privateKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)obj;
        var publicKey = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(
            false, privateKey.Modulus, privateKey.PublicExponent);
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    private Org.BouncyCastle.X509.X509Certificate LoadCertificateFromPem(string pem)
    {
        using var sr = new StringReader(pem);
        var reader = new PemReader(sr);
        return (Org.BouncyCastle.X509.X509Certificate)reader.ReadObject();
    }

    public AsymmetricCipherKeyPair GenerateRsaKeyPair(int keySize)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(
            new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }

    private Org.BouncyCastle.X509.X509Certificate CreateRootCACertificate(
        AsymmetricCipherKeyPair keyPair)
    {
        var gen = new X509V3CertificateGenerator();
        var serial = BigInteger.ProbablePrime(120, new Random());
        var subject = new X509Name("CN=PKI Root CA, O=MasterRad PKI, C=RS");

        gen.SetSerialNumber(serial);
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(subject);
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddYears(20));
        gen.SetPublicKey(keyPair.Public);

        gen.AddExtension(X509Extensions.BasicConstraints, true,
            new BasicConstraints(true));
        gen.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));

        var signer = new Asn1SignatureFactory("SHA256WithRSAEncryption",
            keyPair.Private, new SecureRandom());
        return gen.Generate(signer);
    }

    private Org.BouncyCastle.X509.X509Certificate CreateIntermediateCACertificate(
        AsymmetricCipherKeyPair keyPair,
        Org.BouncyCastle.X509.X509Certificate issuerCert,
        AsymmetricCipherKeyPair issuerKeyPair)
    {
        var gen = new X509V3CertificateGenerator();
        var serial = BigInteger.ProbablePrime(120, new Random());
        var subject = new X509Name("CN=PKI Intermediate CA, O=MasterRad PKI, C=RS");

        gen.SetSerialNumber(serial);
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(issuerCert.SubjectDN);
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddYears(10));
        gen.SetPublicKey(keyPair.Public);

        gen.AddExtension(X509Extensions.BasicConstraints, true,
            new BasicConstraints(0));
        gen.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));
        gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    issuerCert.GetPublicKey())));

        var signer = new Asn1SignatureFactory("SHA256WithRSAEncryption",
            issuerKeyPair.Private, new SecureRandom());
        return gen.Generate(signer);
    }

    private void SaveCAToMongo()
    {
        var rootKeyRecord = new CaKeyRecord
        {
            CaType = "RootCA",
            EncryptedPrivateKey = _encryption.Encrypt(ConvertPrivateKeyToPem(_rootKeyPair!)),
            PublicKeyCertificatePem = ConvertToPem(_rootCertificate!),
            CreatedAt = DateTime.UtcNow
        };

        var intermediateKeyRecord = new CaKeyRecord
        {
            CaType = "IntermediateCA",
            EncryptedPrivateKey = _encryption.Encrypt(ConvertPrivateKeyToPem(_intermediateKeyPair!)),
            PublicKeyCertificatePem = ConvertToPem(_intermediateCertificate!),
            CreatedAt = DateTime.UtcNow
        };

        _mongo.CaKeys.InsertOne(rootKeyRecord);
        _mongo.CaKeys.InsertOne(intermediateKeyRecord);

        // Sacuvaj i u certificates kolekciju
        var existing = _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.In(
                c => c.CertificateType, new[] { "RootCA", "IntermediateCA" }))
            .ToList();

        if (existing.Count == 0)
        {
            _mongo.Certificates.InsertOne(new CertificateRecord
            {
                SerialNumber = _rootCertificate!.SerialNumber.ToString(),
                SubjectName = _rootCertificate.SubjectDN.ToString(),
                IssuerName = _rootCertificate.IssuerDN.ToString(),
                CertificateType = "RootCA",
                IssuedAt = _rootCertificate.NotBefore,
                ExpiresAt = _rootCertificate.NotAfter,
                Status = "Active",
                PemCertificate = ConvertToPem(_rootCertificate)
            });

            _mongo.Certificates.InsertOne(new CertificateRecord
            {
                SerialNumber = _intermediateCertificate!.SerialNumber.ToString(),
                SubjectName = _intermediateCertificate.SubjectDN.ToString(),
                IssuerName = _intermediateCertificate.IssuerDN.ToString(),
                CertificateType = "IntermediateCA",
                IssuedAt = _intermediateCertificate.NotBefore,
                ExpiresAt = _intermediateCertificate.NotAfter,
                Status = "Active",
                IssuedBySerial = _rootCertificate.SerialNumber.ToString(),
                PemCertificate = ConvertToPem(_intermediateCertificate)
            });
        }

        Console.WriteLine("CA kljucevi enkriptovani i sacuvani u MongoDB.");
    }

    public string ConvertToPem(Org.BouncyCastle.X509.X509Certificate cert)
    {
        using var sw = new StringWriter();
        var writer = new PemWriter(sw);
        writer.WriteObject(cert);
        return sw.ToString();
    }

    private string ConvertPrivateKeyToPem(AsymmetricCipherKeyPair keyPair)
    {
        using var sw = new StringWriter();
        var writer = new PemWriter(sw);
        writer.WriteObject(keyPair.Private);
        return sw.ToString();
    }
}