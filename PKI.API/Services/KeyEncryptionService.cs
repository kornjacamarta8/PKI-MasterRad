using System.Security.Cryptography;
using System.Text;

namespace PKI.API.Services;

public class KeyEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public KeyEncryptionService(IConfiguration configuration)
    {
        // U produkciji ovo bi bilo u Azure Key Vault ili HSM
        // Za master rad koristimo konfiguraciju
        var secret = configuration["CaEncryption:Secret"] 
            ?? "PKI-MasterRad-SecretKey-2026-Singidunum";
        var salt = configuration["CaEncryption:Salt"] 
            ?? "PKI-Salt-MasterRad";

        using var deriveBytes = new Rfc2898DeriveBytes(
            Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes(salt),
            100_000,
            HashAlgorithmName.SHA256);

        _key = deriveBytes.GetBytes(32); // AES-256
        _iv = deriveBytes.GetBytes(16);  // AES block size
    }

    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        return Convert.ToBase64String(encryptedBytes);
    }

    public string Decrypt(string cipherText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        using var decryptor = aes.CreateDecryptor();
        var cipherBytes = Convert.FromBase64String(cipherText);
        var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        return Encoding.UTF8.GetString(plainBytes);
    }
}