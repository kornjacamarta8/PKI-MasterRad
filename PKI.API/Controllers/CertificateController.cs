using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private readonly CertificateService _certService;

    public CertificateController(CertificateService certService)
    {
        _certService = certService;
    }

    /// <summary>
    /// Izdaje novi sertifikat za krajnji entitet
    /// </summary>
    [HttpPost("issue")]
    public IActionResult IssueCertificate([FromBody] IssueCertificateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CommonName))
            return BadRequest("CommonName je obavezan.");

        var record = _certService.IssueCertificate(
            request.CommonName,
            request.Organization ?? "Unknown",
            request.Country ?? "RS",
            request.ValidityDays > 0 ? request.ValidityDays : 365
        );

        return Ok(record);
    }

    /// <summary>
    /// Lista svih sertifikata u sistemu
    /// </summary>
    [HttpGet]
    public IActionResult GetAll()
    {
        var certs = _certService.GetAll();
        return Ok(certs);
    }

    /// <summary>
    /// Detalji sertifikata po serijskom broju
    /// </summary>
    [HttpGet("{serialNumber}")]
    public IActionResult GetBySerial(string serialNumber)
    {
        var cert = _certService.GetBySerial(serialNumber);
        if (cert == null)
            return NotFound($"Sertifikat sa serijskim brojem {serialNumber} nije pronadjen.");
        return Ok(cert);
    }

    /// <summary>
    /// Filtriranje sertifikata po statusu: Active, Revoked, Expired
    /// </summary>
    [HttpGet("status/{status}")]
    public IActionResult GetByStatus(string status)
    {
        var certs = _certService.GetByStatus(status);
        return Ok(certs);
    }
}

public class IssueCertificateRequest
{
    public string CommonName { get; set; } = null!;
    public string? Organization { get; set; }
    public string? Country { get; set; }
    public int ValidityDays { get; set; } = 365;
}