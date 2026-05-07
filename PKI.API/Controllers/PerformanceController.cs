using Microsoft.AspNetCore.Mvc;
using PKI.API.Services;

namespace PKI.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PerformanceController : ControllerBase
{
    private readonly PerformanceService _perfService;
    private readonly AuditService _auditService;

    public PerformanceController(PerformanceService perfService, AuditService auditService)
    {
        _perfService = perfService;
        _auditService = auditService;
    }

    /// <summary>
    /// Benchmark generisanja RSA ključeva - 1024, 2048, 4096 bita.
    /// Iterations = broj ponavljanja po veličini (default 3, max preporučeno 5).
    /// </summary>
    [HttpGet("benchmark/keygen")]
    public IActionResult BenchmarkKeyGeneration([FromQuery] int iterations = 3)
    {
        if (iterations < 1 || iterations > 10)
            return BadRequest("Iterations mora biti između 1 i 10.");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var results = _perfService.BenchmarkKeyGeneration(iterations);

        _auditService.Log("PerformanceBenchmark", true, ip,
            details: $"Keygen benchmark, {iterations} iteracija po velicini");

        return Ok(new
        {
            Description = "RSA Key Generation Benchmark",
            Iterations = iterations,
            Results = results,
            Conclusion = results.Select(r => new
            {
                r.KeySize,
                r.AverageMs,
                SecurityLevel = r.KeySize switch
                {
                    1024 => "Nije preporučeno (zastarelo)",
                    2048 => "Minimalno prihvatljivo (NIST do 2030)",
                    4096 => "Visoka sigurnost (preporučeno za CA)",
                    _ => "Nepoznato"
                }
            })
        });
    }

    /// <summary>
    /// Komparativna analiza - poređenje sa industrijskim PKI rešenjima
    /// (Let's Encrypt, OpenSSL, EJBCA)
    /// </summary>
    [HttpGet("comparison")]
    public IActionResult GetComparison()
    {
        var result = _perfService.CompareWithIndustryStandards();
        return Ok(result);
    }
}