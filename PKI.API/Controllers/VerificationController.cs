using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VerificationController : ControllerBase
{
    private readonly VerificationService _verificationService;

    public VerificationController(VerificationService verificationService)
    {
        _verificationService = verificationService;
    }

    /// <summary>
    /// Verifikuje sertifikat po serijskom broju - provjerava lanac poverenja, 
    /// potpis, validnost i status opoziva
    /// </summary>
    [HttpGet("verify/{serialNumber}")]
    public IActionResult VerifyBySerial(string serialNumber)
    {
        var result = _verificationService.VerifyBySerial(serialNumber);
        return Ok(result);
    }

    /// <summary>
    /// Verifikuje sertifikat na osnovu PEM sadrzaja
    /// </summary>
    [HttpPost("verify-pem")]
    public IActionResult VerifyByPem([FromBody] VerifyPemRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.PemCertificate))
            return BadRequest("PEM sertifikat je obavezan.");

        var result = _verificationService.VerifyByPem(request.PemCertificate);
        return Ok(result);
    }

    /// <summary>
    /// Vraca trenutni status sertifikata (OCSP-like)
    /// </summary>
    [HttpGet("status/{serialNumber}")]
    public IActionResult GetStatus(string serialNumber)
    {
        var result = _verificationService.VerifyBySerial(serialNumber);

        return Ok(new
        {
            SerialNumber = serialNumber,
            Status = result.IsRevoked ? "Revoked" :
                     result.IsExpired ? "Expired" :
                     result.IsValid ? "Good" : "Unknown",
            IsValid = result.IsValid,
            IsRevoked = result.IsRevoked,
            RevocationReason = result.RevocationReason,
            IsExpired = result.IsExpired,
            CheckedAt = DateTime.UtcNow
        });
    }
}

public class VerifyPemRequest
{
    public string PemCertificate { get; set; } = null!;
}