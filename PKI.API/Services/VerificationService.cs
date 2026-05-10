using MongoDB.Driver;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using PKI.API.Models;

namespace PKI.API.Services;

public class VerificationResult
{
    public bool IsValid { get; set; }
    public string SerialNumber { get; set; } = null!;
    public string SubjectName { get; set; } = null!;
    public string IssuerName { get; set; } = null!;
    public string Status { get; set; } = null!;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public bool IsExpired { get; set; }
    public bool IsRevoked { get; set; }
    public string? RevocationReason { get; set; }
    public bool SignatureValid { get; set; }
    public bool ChainValid { get; set; }
    public List<string> ChainPath { get; set; } = new();
    public List<string> Errors { get; set; } = new();
}

public class VerificationService
{
    private readonly MongoDbService _mongo;
    private readonly CertificateAuthorityService _caService;

    public VerificationService(MongoDbService mongo, CertificateAuthorityService caService)
    {
        _mongo = mongo;
        _caService = caService;
    }

    public VerificationResult VerifyBySerial(string serialNumber)
    {
        var record = _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Eq(c => c.SerialNumber, serialNumber))
            .FirstOrDefault();

        if (record == null)
            return new VerificationResult
            {
                IsValid = false,
                Errors = new List<string> { $"Sertifikat sa serijskim brojem {serialNumber} nije pronadjen." }
            };

        return VerifyRecord(record);
    }

    public VerificationResult VerifyByPem(string pemCertificate)
    {
        Org.BouncyCastle.X509.X509Certificate cert;
        try
        {
            using var sr = new StringReader(pemCertificate);
            var reader = new PemReader(sr);
            cert = (Org.BouncyCastle.X509.X509Certificate)reader.ReadObject();
        }
        catch
        {
            return new VerificationResult
            {
                IsValid = false,
                Errors = new List<string> { "Nevazeci PEM format sertifikata." }
            };
        }

        var serialNumber = cert.SerialNumber.ToString();
        var record = _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Eq(c => c.SerialNumber, serialNumber))
            .FirstOrDefault();

        if (record == null)
            return new VerificationResult
            {
                IsValid = false,
                SerialNumber = serialNumber,
                SubjectName = cert.SubjectDN.ToString(),
                IssuerName = cert.IssuerDN.ToString(),
                Errors = new List<string> { "Sertifikat nije pronadjen u ovom PKI sistemu." }
            };

        return VerifyRecord(record);
    }

    private VerificationResult VerifyRecord(CertificateRecord record)
    {
        var result = new VerificationResult
        {
            SerialNumber = record.SerialNumber,
            SubjectName = record.SubjectName,
            IssuerName = record.IssuerName,
            ValidFrom = record.IssuedAt,
            ValidTo = record.ExpiresAt,
            IsExpired = DateTime.UtcNow > record.ExpiresAt,
            IsRevoked = record.Status == "Revoked",
            RevocationReason = record.RevocationReason
        };

        // Parsiranje sertifikata
        Org.BouncyCastle.X509.X509Certificate cert;
        using (var sr = new StringReader(record.PemCertificate))
        {
            var reader = new PemReader(sr);
            cert = (Org.BouncyCastle.X509.X509Certificate)reader.ReadObject();
        }

        // Provjera isteka
        if (result.IsExpired)
            result.Errors.Add($"Sertifikat je istekao: {record.ExpiresAt:yyyy-MM-dd}");

        // Provjera opoziva
        if (result.IsRevoked)
            result.Errors.Add($"Sertifikat je opozvan. Razlog: {record.RevocationReason}");

        // Provjera potpisa i lanca poverenja
        result.ChainValid = VerifyChain(cert, record, result);
        result.SignatureValid = result.ChainValid;

        // Status
        result.Status = record.Status;
        result.IsValid = !result.IsExpired && !result.IsRevoked
            && result.ChainValid && result.Errors.Count == 0;

        return result;
    }

    private bool VerifyChain(
        Org.BouncyCastle.X509.X509Certificate cert,
        CertificateRecord record,
        VerificationResult result)
    {
        try
        {
            if (record.CertificateType == "RootCA")
            {
                // Root CA verifikuje sam sebe
                cert.Verify(cert.GetPublicKey());
                result.ChainPath.Add($"Root CA: {record.SubjectName}");
                return true;
            }

            if (record.CertificateType == "IntermediateCA")
            {
                if (_caService.RootCertificate == null)
                {
                    result.Errors.Add("Root CA nije dostupan za verifikaciju.");
                    return false;
                }
                cert.Verify(_caService.RootCertificate.GetPublicKey());
                result.ChainPath.Add($"Root CA: {_caService.RootCertificate.SubjectDN}");
                result.ChainPath.Add($"Intermediate CA: {record.SubjectName}");
                return true;
            }

            // EndEntity — proveri lanac do root-a
            if (_caService.IntermediateCertificate == null || _caService.RootCertificate == null)
            {
                result.Errors.Add("CA sertifikati nisu dostupni za verifikaciju lanca.");
                return false;
            }

            // Korak 1: EndEntity potpisan od Intermediate CA?
            cert.Verify(_caService.IntermediateCertificate.GetPublicKey());

            // Korak 2: Intermediate CA potpisan od Root CA?
            _caService.IntermediateCertificate.Verify(_caService.RootCertificate.GetPublicKey());

            // Korak 3: Root CA self-signed?
            _caService.RootCertificate.Verify(_caService.RootCertificate.GetPublicKey());

            result.ChainPath.Add($"Root CA: {_caService.RootCertificate.SubjectDN}");
            result.ChainPath.Add($"Intermediate CA: {_caService.IntermediateCertificate.SubjectDN}");
            result.ChainPath.Add($"End Entity: {record.SubjectName}");
            return true;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Greska u verifikaciji lanca: {ex.Message}");
            return false;
        }
    }
}