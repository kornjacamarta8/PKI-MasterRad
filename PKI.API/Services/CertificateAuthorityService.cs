using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PKI.API.Models;
using MongoDB.Driver;

namespace PKI.API.Services;

public class CertificateAuthorityService
{
    private readonly MongoDbService _mongo;

    // In-memory storage za privatne kljuceve (u produkciji bi bio HSM)
    private AsymmetricCipherKeyPair? _rootKeyPair;
    private AsymmetricCipherKeyPair? _intermediateKeyPair;
    private Org.BouncyCastle.X509.X509Certificate? _rootCertificate;
    private Org.BouncyCastle.X509.X509Certificate? _intermediateCertificate;

    public Org.BouncyCastle.X509.X509Certificate? RootCertificate => _rootCertificate;
    public Org.BouncyCastle.X509.X509Certificate? IntermediateCertificate => _intermediateCertificate;
    public AsymmetricCipherKeyPair? IntermediateKeyPair => _intermediateKeyPair;

    public CertificateAuthorityService(MongoDbService mongo)
    {
        _mongo = mongo;
    }

    public void InitializeCA()
    {
        Console.WriteLine("Inicijalizacija PKI infrastrukture...");
        _rootKeyPair = GenerateRsaKeyPair(4096);
        _rootCertificate = CreateRootCACertificate(_rootKeyPair);

        _intermediateKeyPair = GenerateRsaKeyPair(2048);
        _intermediateCertificate = CreateIntermediateCACertificate(
            _intermediateKeyPair, _rootCertificate, _rootKeyPair);

        SaveCAToMongo();
        Console.WriteLine("PKI infrastruktura uspesno inicijalizovana.");
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
        gen.SetIssuerDN(subject); // self-signed
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddYears(20));
        gen.SetPublicKey(keyPair.Public);

        // X.509 v3 ekstenzije
        gen.AddExtension(X509Extensions.BasicConstraints, true,
            new BasicConstraints(true)); // isCA = true
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
            new BasicConstraints(0)); // pathLen=0, ne moze dalje da potpisuje CA
        gen.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));
        gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerCert.GetPublicKey())));

        var signer = new Asn1SignatureFactory("SHA256WithRSAEncryption",
            issuerKeyPair.Private, new SecureRandom());
        return gen.Generate(signer);
    }

    private void SaveCAToMongo()
    {
        // Provjeri da li vec postoje u bazi
        var existing = _mongo.Certificates
        .Find(Builders<CertificateRecord>.Filter.In(c => c.CertificateType, new[] { "RootCA", "IntermediateCA" }))
        .ToList();

        if (existing.Count > 0)
        {
            Console.WriteLine("CA sertifikati vec postoje u bazi, preskacemo.");
            return;
        }

        var rootRecord = new CertificateRecord
        {
            SerialNumber = _rootCertificate!.SerialNumber.ToString(),
            SubjectName = _rootCertificate.SubjectDN.ToString(),
            IssuerName = _rootCertificate.IssuerDN.ToString(),
            CertificateType = "RootCA",
            IssuedAt = _rootCertificate.NotBefore,
            ExpiresAt = _rootCertificate.NotAfter,
            Status = "Active",
            PemCertificate = ConvertToPem(_rootCertificate)
        };

        var intermediateRecord = new CertificateRecord
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
        };

        _mongo.Certificates.InsertOne(rootRecord);
        _mongo.Certificates.InsertOne(intermediateRecord);
        Console.WriteLine("CA sertifikati sacuvani u MongoDB.");
    }

    public string ConvertToPem(Org.BouncyCastle.X509.X509Certificate cert)
    {
        using var sw = new StringWriter();
        var writer = new PemWriter(sw);
        writer.WriteObject(cert);
        return sw.ToString();
    }
}