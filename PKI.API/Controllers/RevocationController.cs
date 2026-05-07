using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RevocationController : ControllerBase
{
    private readonly RevocationService _revocationService;

    public RevocationController(RevocationService revocationService)
    {
        _revocationService = revocationService;
    }

    /// <summary>
    /// Opoziva sertifikat po serijskom broju
    /// </summary>
    [HttpPost("revoke/{serialNumber}")]
    public IActionResult Revoke(string serialNumber, [FromBody] RevokeRequest request)
    {
        var success = _revocationService.RevokeCertificate(
            serialNumber,
            request.Reason ?? "Unspecified");

        if (!success)
            return BadRequest("Sertifikat nije pronadjen ili je vec opozvan.");

        return Ok(new
        {
            Message = $"Sertifikat {serialNumber} uspesno opozvan.",
            Reason = request.Reason
        });
    }

    /// <summary>
    /// Generise CRL (Certificate Revocation List) u PEM formatu
    /// </summary>
    [HttpGet("crl")]
    public IActionResult GetCRL()
    {
        var crl = _revocationService.GenerateCRL();
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