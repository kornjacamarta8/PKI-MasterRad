using MongoDB.Driver;
using PKI.API.Models;

namespace PKI.API.Services;

public class StatisticsResult
{
    public int TotalCertificates { get; set; }
    public int ActiveCertificates { get; set; }
    public int RevokedCertificates { get; set; }
    public int ExpiredCertificates { get; set; }
    public int CACertificates { get; set; }
    public int EndEntityCertificates { get; set; }
    public double AverageValidityDays { get; set; }
    public DateTime? LastIssuedAt { get; set; }
    public DateTime? LastRevokedAt { get; set; }
    public Dictionary<string, int> RevocationReasons { get; set; } = new();
    public List<MonthlyStat> IssuedPerMonth { get; set; } = new();
}

public class MonthlyStat
{
    public string Month { get; set; } = null!;
    public int Count { get; set; }
}

public class StatisticsService
{
    private readonly MongoDbService _mongo;

    public StatisticsService(MongoDbService mongo)
    {
        _mongo = mongo;
    }

    public StatisticsResult GetStatistics()
    {
        var all = _mongo.Certificates
            .Find(Builders<CertificateRecord>.Filter.Empty)
            .ToList();

        var now = DateTime.UtcNow;
        var endEntities = all.Where(c => c.CertificateType == "EndEntity").ToList();
        var revoked = all.Where(c => c.Status == "Revoked").ToList();
        var expired = all.Where(c => c.Status == "Active" && c.ExpiresAt < now).ToList();

        var result = new StatisticsResult
        {
            TotalCertificates = all.Count,
            ActiveCertificates = all.Count(c => c.Status == "Active" && c.ExpiresAt >= now),
            RevokedCertificates = revoked.Count,
            ExpiredCertificates = expired.Count,
            CACertificates = all.Count(c =>
                c.CertificateType == "RootCA" || c.CertificateType == "IntermediateCA"),
            EndEntityCertificates = endEntities.Count,
            LastIssuedAt = all.OrderByDescending(c => c.IssuedAt).FirstOrDefault()?.IssuedAt,
            LastRevokedAt = revoked.OrderByDescending(c => c.RevokedAt).FirstOrDefault()?.RevokedAt
        };

        // Prosjecni period vaznosti (samo EndEntity)
        if (endEntities.Any())
        {
            result.AverageValidityDays = endEntities
                .Average(c => (c.ExpiresAt - c.IssuedAt).TotalDays);
        }

        // Razlozi opoziva
        result.RevocationReasons = revoked
            .GroupBy(c => c.RevocationReason ?? "Unspecified")
            .ToDictionary(g => g.Key, g => g.Count());

        // Izdati sertifikati po mjesecu (zadnjih 12 mjeseci)
        result.IssuedPerMonth = all
            .Where(c => c.IssuedAt >= now.AddMonths(-12))
            .GroupBy(c => c.IssuedAt.ToString("yyyy-MM"))
            .Select(g => new MonthlyStat { Month = g.Key, Count = g.Count() })
            .OrderBy(m => m.Month)
            .ToList();

        return result;
    }
}