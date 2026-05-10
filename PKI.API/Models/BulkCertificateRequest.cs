namespace PKI.API.Models;

public class BulkCertificateRequest
{
    public string CommonName { get; set; } = null!;
    public string? Organization { get; set; }
    public string? Country { get; set; }
    public int ValidityDays { get; set; } = 365;
}