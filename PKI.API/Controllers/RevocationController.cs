using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RevocationController : ControllerBase
{
    private readonly RevocationService _revocationService;
    private readonly AuditService _auditService;

    public RevocationController(RevocationService revocationService, AuditService auditService)
    {
        _revocationService = revocationService;
        _auditService = auditService;
    }

    [HttpPost("revoke/{serialNumber}")]
    public IActionResult Revoke(string serialNumber, [FromBody] RevokeRequest request)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var success = _revocationService.RevokeCertificate(
            serialNumber, request.Reason ?? "Unspecified");

        if (!success)
        {
            _auditService.Log("RevokeCertificate", false, ip, serialNumber,
                errorMessage: "Sertifikat nije pronadjen ili je vec opozvan.");
            return BadRequest("Sertifikat nije pronadjen ili je vec opozvan.");
        }

        _auditService.Log("RevokeCertificate", true, ip, serialNumber,
            details: $"Razlog: {request.Reason}");

        return Ok(new
        {
            Message = $"Sertifikat {serialNumber} uspjesno opozvan.",
            Reason = request.Reason
        });
    }

    [HttpGet("crl")]
    public IActionResult GetCRL()
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var crl = _revocationService.GenerateCRL();

        _auditService.Log("GenerateCRL", true, ip,
            details: "CRL generisan na zahtjev");

        return Ok(new
        {
            GeneratedAt = DateTime.UtcNow,
            NextUpdate = DateTime.UtcNow.AddDays(7),
            Crl = crl
        });
    }
}

public class RevokeRequest
{
    /// <summary>
    /// Razlozi: Unspecified, KeyCompromise, CACompromise,
    /// AffiliationChanged, Superseded, CessationOfOperation
    /// </summary>
    public string? Reason { get; set; }
}