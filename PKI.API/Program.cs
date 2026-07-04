using Microsoft.OpenApi.Models;
using PKI.API.Services;
using PKI.API.Settings;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// CORS - dozvoljava frontend-u (wwwroot/index.html ili bilo koji drugi origin) da zove API
builder.Services.AddCors(options =>
{
    options.AddPolicy("FrontendPolicy", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "PKI Management API",
        Version = "v1",
        Description = "PKI infrastruktura - upravljanje digitalnim sertifikatima"
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
    c.RoutePrefix = "swagger";
});

app.UseDefaultFiles();         // koren "/" sada traži wwwroot/index.html
app.UseStaticFiles();          // servira wwwroot/index.html
app.UseCors("FrontendPolicy"); // mora biti pre MapControllers
app.UseAuthorization();
app.MapControllers();

// Inicijalizacija CA pri startu
var caService = app.Services.GetRequiredService<CertificateAuthorityService>();
caService.InitializeCA();

app.Run();