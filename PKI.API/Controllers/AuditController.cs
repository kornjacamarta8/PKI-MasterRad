using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuditController : ControllerBase
{
    private readonly AuditService _auditService;

    public AuditController(AuditService auditService)
    {
        _auditService = auditService;
    }

    /// <summary>
    /// Zadnjih N audit log zapisa (default 50)
    /// </summary>
    [HttpGet]
    public IActionResult GetLogs([FromQuery] int limit = 50)
    {
        var logs = _auditService.GetLogs(limit);
        return Ok(logs);
    }

    /// <summary>
    /// Audit log po tipu akcije - koristi query param:
    /// /api/Audit/filter?action=IssueCertificate
    /// /api/Audit/filter?action=RevokeCertificate
    /// /api/Audit/filter?action=GenerateCRL
    /// </summary>
    [HttpGet("filter")]
    public IActionResult Filter(
        [FromQuery] string? action = null,
        [FromQuery] string? serialNumber = null)
    {
        if (!string.IsNullOrEmpty(serialNumber))
        {
            var bySerial = _auditService.GetLogsBySerial(serialNumber);
            return Ok(bySerial);
        }

        if (!string.IsNullOrEmpty(action))
        {
            var byAction = _auditService.GetLogsByAction(action);
            return Ok(byAction);
        }

        return BadRequest("Navedi action ili serialNumber query parametar.");
    }
}