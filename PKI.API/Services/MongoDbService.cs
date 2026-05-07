using Microsoft.Extensions.Options;
using MongoDB.Driver;
using PKI.API.Models;
using PKI.API.Settings;

namespace PKI.API.Services;

public class MongoDbService
{
    private readonly IMongoDatabase _database;

    public MongoDbService(IOptions<MongoDbSettings> settings)
    {
        var client = new MongoClient(settings.Value.ConnectionString);
        _database = client.GetDatabase(settings.Value.DatabaseName);
    }

    public IMongoCollection<CertificateRecord> Certificates =>
        _database.GetCollection<CertificateRecord>("certificates");
}