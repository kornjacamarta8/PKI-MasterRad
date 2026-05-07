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
}