using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CaController : ControllerBase
{
    private readonly CertificateAuthorityService _caService;

    public CaController(CertificateAuthorityService caService)
    {
        _caService = caService;
    }

    /// <summary>
    /// Vraca PEM sertifikat Root CA
    /// </summary>
    [HttpGet("root")]
    public IActionResult GetRootCertificate()
    {
        if (_caService.RootCertificate == null)
            return NotFound("Root CA nije inicijalizovan.");

        return Ok(new
        {
            Subject = _caService.RootCertificate.SubjectDN.ToString(),
            Issuer = _caService.RootCertificate.IssuerDN.ToString(),
            SerialNumber = _caService.RootCertificate.SerialNumber.ToString(),
            ValidFrom = _caService.RootCertificate.NotBefore,
            ValidTo = _caService.RootCertificate.NotAfter,
            PemCertificate = _caService.ConvertToPem(_caService.RootCertificate)
        });
    }

    /// <summary>
    /// Vraca PEM sertifikat Intermediate CA
    /// </summary>
    [HttpGet("intermediate")]
    public IActionResult GetIntermediateCertificate()
    {
        if (_caService.IntermediateCertificate == null)
            return NotFound("Intermediate CA nije inicijalizovan.");

        return Ok(new
        {
            Subject = _caService.IntermediateCertificate.SubjectDN.ToString(),
            Issuer = _caService.IntermediateCertificate.IssuerDN.ToString(),
            SerialNumber = _caService.IntermediateCertificate.SerialNumber.ToString(),
            ValidFrom = _caService.IntermediateCertificate.NotBefore,
            ValidTo = _caService.IntermediateCertificate.NotAfter,
            PemCertificate = _caService.ConvertToPem(_caService.IntermediateCertificate)
        });
    }
}