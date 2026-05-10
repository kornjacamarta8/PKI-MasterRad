using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class StatisticsController : ControllerBase
{
    private readonly StatisticsService _statsService;
    private readonly AuditService _auditService;

    public StatisticsController(StatisticsService statsService, AuditService auditService)
    {
        _statsService = statsService;
        _auditService = auditService;
    }

    /// <summary>
    /// Pregled statistike PKI sistema - broj sertifikata po statusu,
    /// prosjecni period vaznosti, izdati po mjesecu
    /// </summary>
    [HttpGet]
    public IActionResult GetStatistics()
    {
        var stats = _statsService.GetStatistics();
        return Ok(stats);
    }

    /// <summary>
    /// Sertifikati kojima istice vaznost u zadatom broju dana (default 30)
    /// </summary>
    [HttpGet("expiring")]
    public IActionResult GetExpiring([FromQuery] int withinDays = 30)
    {
        var certService = HttpContext.RequestServices
            .GetRequiredService<CertificateService>();
        var serials = certService.GetExpiringCertificates(withinDays);
        return Ok(new
        {
            WithinDays = withinDays,
            Count = serials.Count,
            SerialNumbers = serials
        });
    }
}