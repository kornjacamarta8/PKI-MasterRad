using MongoDB.Driver;
using PKI.API.Models;

namespace PKI.API.Services;

public class AuditService
{
    private readonly MongoDbService _mongo;

    public AuditService(MongoDbService mongo)
    {
        _mongo = mongo;
    }

    public void Log(string action, bool success, string ipAddress,
        string? serialNumber = null, string? subjectName = null,
        string? details = null, string? errorMessage = null)
    {
        var record = new AuditLogRecord
        {
            Action = action,
            Success = success,
            IpAddress = ipAddress,
            SerialNumber = serialNumber,
            SubjectName = subjectName,
            Details = details,
            ErrorMessage = errorMessage,
            Timestamp = DateTime.UtcNow
        };

        _mongo.AuditLogs.InsertOne(record);
    }

    public List<AuditLogRecord> GetLogs(int limit = 50) =>
        _mongo.AuditLogs
            .Find(Builders<AuditLogRecord>.Filter.Empty)
            .SortByDescending(a => a.Timestamp)
            .Limit(limit)
            .ToList();

    public List<AuditLogRecord> GetLogsByAction(string action) =>
        _mongo.AuditLogs
            .Find(Builders<AuditLogRecord>.Filter.Eq(a => a.Action, action))
            .SortByDescending(a => a.Timestamp)
            .ToList();

    public List<AuditLogRecord> GetLogsBySerial(string serialNumber) =>
        _mongo.AuditLogs
            .Find(Builders<AuditLogRecord>.Filter.Eq(a => a.SerialNumber, serialNumber))
            .SortByDescending(a => a.Timestamp)
            .ToList();
}