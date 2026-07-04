using System.Security.Cryptography;
using System.Text;

namespace PKI.API.Services;

public class KeyEncryptionService
{
    private readonly byte[] _key;

    private const int NonceSize = 12; // AES-GCM standard nonce (96-bit)
    private const int TagSize = 16;   // AES-GCM auth tag (128-bit)

    public KeyEncryptionService(IConfiguration configuration)
    {
        // U produkciji ovo bi bilo u Azure Key Vault ili HSM.
        // Namerno NEMA podrazumevane (hardkodovane) vrednosti - ako konfiguracija
        // nedostaje, sistem treba glasno da otkaze umesto da tiho koristi
        // vrednost koja je vidljiva u izvornom kodu.
        var secret = configuration["CaEncryption:Secret"];
        var salt = configuration["CaEncryption:Salt"];

        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(salt))
        {
            throw new InvalidOperationException(
                "CaEncryption:Secret i CaEncryption:Salt moraju biti podeseni " +
                "(appsettings.json, environment varijable ili User Secrets) - " +
                "sistem namerno ne koristi podrazumevanu (hardkodovanu) vrednost " +
                "za enkripciju privatnih kljuceva CA.");
        }

        using var deriveBytes = new Rfc2898DeriveBytes(
            Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes(salt),
            100_000,
            HashAlgorithmName.SHA256);

        _key = deriveBytes.GetBytes(32); // AES-256 kljuc
        // IV/nonce se VISE NE izvodi ovde jedanput - generise se nasumicno
        // pri svakoj pojedinacnoj enkripciji (vidi Encrypt ispod).
    }

    /// <summary>
    /// AES-256-GCM enkripcija sa nasumicnim nonce-om po pozivu.
    /// Izlaz (Base64) = nonce (12B) || tag (16B) || ciphertext.
    /// GCM istovremeno obezbedjuje poverljivost I integritet (autentifikovana
    /// enkripcija), za razliku od prethodne CBC-only implementacije koja nije
    /// stitila od neovlascene izmene ciphertext-a (padding oracle rizik).
    /// </summary>
    public string Encrypt(string plainText)
    {
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce); // nov, kriptografski siguran nonce za SVAKI poziv

        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[TagSize];

        using (var aesGcm = new AesGcm(_key, TagSize))
        {
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);
        }

        var output = new byte[NonceSize + TagSize + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, output, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, output, NonceSize, TagSize);
        Buffer.BlockCopy(cipherBytes, 0, output, NonceSize + TagSize, cipherBytes.Length);

        return Convert.ToBase64String(output);
    }

    public string Decrypt(string cipherText)
    {
        var input = Convert.FromBase64String(cipherText);

        if (input.Length < NonceSize + TagSize)
            throw new CryptographicException("Neispravan sifrovan sadrzaj (prekratak za nonce+tag).");

        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var cipherBytes = new byte[input.Length - NonceSize - TagSize];

        Buffer.BlockCopy(input, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(input, NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(input, NonceSize + TagSize, cipherBytes, 0, cipherBytes.Length);

        var plainBytes = new byte[cipherBytes.Length];
        using (var aesGcm = new AesGcm(_key, TagSize))
        {
            // Ako je ciphertext izmenjen (ili je koriscen pogresan kljuc), GCM
            // ce ovde baciti CryptographicException umesto da tiho vrati sme#e -
            // to je ta "integrity" provera koje je stara CBC implementacija bila lisena.
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);
        }

        return Encoding.UTF8.GetString(plainBytes);
    }
}