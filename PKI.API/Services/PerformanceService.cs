using System.Diagnostics;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace PKI.API.Services;

public class KeyGenerationBenchmark
{
    public int KeySize { get; set; }
    public double ElapsedMs { get; set; }
    public int Iterations { get; set; }
    public double AverageMs { get; set; }
    public double MinMs { get; set; }
    public double MaxMs { get; set; }
}

public class PerformanceService
{
    public List<KeyGenerationBenchmark> BenchmarkKeyGeneration(int iterations = 3)
    {
        var keySizes = new[] { 1024, 2048, 4096 };
        var results = new List<KeyGenerationBenchmark>();

        foreach (var keySize in keySizes)
        {
            var times = new List<double>();

            for (int i = 0; i < iterations; i++)
            {
                var sw = Stopwatch.StartNew();

                var generator = new RsaKeyPairGenerator();
                generator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(
                    new SecureRandom(), keySize));
                generator.GenerateKeyPair();

                sw.Stop();
                times.Add(sw.Elapsed.TotalMilliseconds);
            }

            results.Add(new KeyGenerationBenchmark
            {
                KeySize = keySize,
                Iterations = iterations,
                ElapsedMs = times.Sum(),
                AverageMs = Math.Round(times.Average(), 2),
                MinMs = Math.Round(times.Min(), 2),
                MaxMs = Math.Round(times.Max(), 2)
            });
        }

        return results;
    }

    public object CompareWithIndustryStandards()
    {
        return new
        {
            ThisSystem = new
            {
                Name = "PKI MasterRad (.NET/BouncyCastle)",
                KeyStorage = "MongoDB + AES-256 enkripcija",
                RevocationMechanism = "CRL + OCSP-like status endpoint",
                CertificateStandard = "X.509 v3 (RFC 5280)",
                CAHierarchy = "Root CA → Intermediate CA → EndEntity",
                KeySizes = "RSA 2048/4096-bit",
                OpenSource = true,
                CloudReady = false,
                HSMSupport = false,
                Scalability = "Niska (single-node, edukaciona svrha)"
            },
            Comparison = new[]
            {
            new {
                Name = "Let's Encrypt",
                KeyStorage = "HSM (Hardware Security Module)",
                RevocationMechanism = "OCSP + CRL",
                CertificateStandard = "X.509 v3 (RFC 5280)",
                CAHierarchy = "Root CA → Intermediate CA → EndEntity",
                KeySizes = "RSA 2048-bit, ECDSA P-256",
                OpenSource = true,
                CloudReady = true,
                HSMSupport = true,
                Scalability = "Visoka (milijarde sertifikata)"
            },
            new {
                Name = "OpenSSL CA",
                KeyStorage = "Fajl sistem (opciono enkriptovan)",
                RevocationMechanism = "CRL",
                CertificateStandard = "X.509 v3 (RFC 5280)",
                CAHierarchy = "Konfigurabilan",
                KeySizes = "RSA, ECDSA, Ed25519",
                OpenSource = true,
                CloudReady = false,
                HSMSupport = true,
                Scalability = "Srednja (manuelna administracija)"
            },
            new {
                Name = "EJBCA (Enterprise)",
                KeyStorage = "HSM + baza podataka",
                RevocationMechanism = "OCSP + CRL + Delta CRL",
                CertificateStandard = "X.509 v3, CV Certificate",
                CAHierarchy = "Višestepena, konfigurabilan",
                KeySizes = "RSA, ECDSA, Ed25519, post-kvantni",
                OpenSource = true,
                CloudReady = true,
                HSMSupport = true,
                Scalability = "Visoka (enterprise nivo)"
            }
        }
        };
    }
}

