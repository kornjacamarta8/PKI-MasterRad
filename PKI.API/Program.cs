using Microsoft.OpenApi.Models;
using PKI.API.Services;
using PKI.API.Settings;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "PKI Management API",
        Version = "v1",
        Description = "Mini PKI infrastruktura - upravljanje digitalnim sertifikatima"
    });
});

// MongoDB settings
builder.Services.Configure<MongoDbSettings>(
    builder.Configuration.GetSection("MongoDbSettings"));

// Services
builder.Services.AddSingleton<MongoDbService>();
builder.Services.AddSingleton<CertificateAuthorityService>();
builder.Services.AddSingleton<KeyEncryptionService>();
builder.Services.AddSingleton<AuditService>();
builder.Services.AddScoped<CertificateService>();
builder.Services.AddScoped<RevocationService>();
builder.Services.AddScoped<VerificationService>();
builder.Services.AddScoped<StatisticsService>();
builder.Services.AddScoped<PerformanceService>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "PKI API v1");
    c.RoutePrefix = string.Empty;
});

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// Inicijalizacija CA pri startu
var caService = app.Services.GetRequiredService<CertificateAuthorityService>();
caService.InitializeCA();

app.Run();