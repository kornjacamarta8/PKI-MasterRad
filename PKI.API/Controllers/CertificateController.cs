// using Microsoft.AspNetCore.Mvc;
// using PKI.API.Services;
// using PKI.API.Models;

// namespace PKI.API.Controllers;

// [ApiController]
// [Route("api/[controller]")]
// public class CertificateController : ControllerBase
// {
//     private readonly CertificateService _certService;
//     private readonly AuditService _auditService;

//     public CertificateController(CertificateService certService, AuditService auditService)
//     {
//         _certService = certService;
//         _auditService = auditService;
//     }

//     [HttpPost("issue")]
//     public IActionResult IssueCertificate([FromBody] IssueCertificateRequest request)
//     {
//         if (string.IsNullOrWhiteSpace(request.CommonName))
//             return BadRequest("CommonName je obavezan.");

//         var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
//         try
//         {
//             var record = _certService.IssueCertificate(
//                 request.CommonName,
//                 request.Organization ?? "Unknown",
//                 request.Country ?? "RS",
//                 request.ValidityDays > 0 ? request.ValidityDays : 365);

//             _auditService.Log("IssueCertificate", true, ip,
//                 record.SerialNumber, record.SubjectName,
//                 $"Izdat sertifikat, validnost: {request.ValidityDays} dana");

//             return Ok(record);
//         }
//         catch (Exception ex)
//         {
//             _auditService.Log("IssueCertificate", false, ip,
//                 details: request.CommonName, errorMessage: ex.Message);
//             return StatusCode(500, ex.Message);
//         }
//     }

//     [HttpPost("issue-bulk")]
//     public IActionResult IssueBulk([FromBody] List<BulkCertificateRequest> requests)
//     {
//         if (requests == null || requests.Count == 0)
//             return BadRequest("Lista zahteva je prazna.");

//         var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
//         var results = _certService.IssueBulk(requests);

//         _auditService.Log("IssueCertificate", true, ip,
//             details: $"Bulk izdavanje: {results.Count} sertifikata");

//         return Ok(results);
//     }

//     [HttpGet]
//     public IActionResult GetAll()
//     {
//         var certs = _certService.GetAll();
//         return Ok(certs);
//     }

//     [HttpGet("{serialNumber}")]
//     public IActionResult GetBySerial(string serialNumber)
//     {
//         var cert = _certService.GetBySerial(serialNumber);
//         if (cert == null)
//             return NotFound($"Sertifikat {serialNumber} nije pronadjen.");
//         return Ok(cert);
//     }

//     [HttpGet("status/{status}")]
//     public IActionResult GetByStatus(string status)
//     {
//         var certs = _certService.GetByStatus(status);
//         return Ok(certs);
//     }
// }

// public class IssueCertificateRequest
// {
//     public string CommonName { get; set; } = null!;
//     public string? Organization { get; set; }
//     public string? Country { get; set; }
//     public int ValidityDays { get; set; } = 365;
// }

using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;
using PKI.API.Models;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private readonly CertificateService _certService;
    private readonly AuditService _auditService;

    public CertificateController(CertificateService certService, AuditService auditService)
    {
        _certService = certService;
        _auditService = auditService;
    }

    [HttpPost("issue")]
    public IActionResult IssueCertificate([FromBody] IssueCertificateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CommonName))
            return BadRequest("CommonName je obavezan.");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        try
        {
            var record = _certService.IssueCertificate(
                request.CommonName,
                request.Organization ?? "Unknown",
                request.Country ?? "RS",
                request.ValidityDays > 0 ? request.ValidityDays : 365);

            _auditService.Log("IssueCertificate", true, ip,
                record.SerialNumber, record.SubjectName,
                $"Izdat sertifikat, validnost: {request.ValidityDays} dana. " +
                "NAPOMENA: privatni kljuc vracen klijentu u odgovoru (demo/edukaciona svrha).");

            return Ok(record);
        }
        catch (Exception ex)
        {
            _auditService.Log("IssueCertificate", false, ip,
                details: request.CommonName, errorMessage: ex.Message);
            return StatusCode(500, ex.Message);
        }
    }

    [HttpPost("issue-bulk")]
    public IActionResult IssueBulk([FromBody] List<BulkCertificateRequest> requests)
    {
        if (requests == null || requests.Count == 0)
            return BadRequest("Lista zahteva je prazna.");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var results = _certService.IssueBulk(requests);

        _auditService.Log("IssueCertificate", true, ip,
            details: $"Bulk izdavanje: {results.Count} sertifikata. " +
            "NAPOMENA: privatni kljucevi vraceni klijentu u odgovoru (demo/edukaciona svrha).");

        return Ok(results);
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var certs = _certService.GetAll();
        return Ok(certs);
    }

    [HttpGet("{serialNumber}")]
    public IActionResult GetBySerial(string serialNumber)
    {
        var cert = _certService.GetBySerial(serialNumber);
        if (cert == null)
            return NotFound($"Sertifikat {serialNumber} nije pronadjen.");
        return Ok(cert);
    }

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