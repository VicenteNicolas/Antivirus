using System.Text.Json;
using SentinelSecurity.Engine;

namespace SentinelSecurity.MachineLearning;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            if (args is ["extract", var manifest, var features])
            {
                await FeatureDataset.ExtractAsync(manifest, features, cancellation.Token);
                return 0;
            }
            if (args is ["train", var input, var directory])
            {
                var result = await TrainingPipeline.TrainAsync(input, directory, cancellation.Token);
                Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            if (args is ["assess", var bundle, var reviewedSha256, var file])
            {
                var model = await ReviewedModel.LoadAsync(bundle, reviewedSha256, cancellation.Token);
                var fileFeatures = await ScanEngine.ExtractFeaturesAsync(file, 128L * 1024 * 1024, cancellation.Token);
                var result = model.Assess(fileFeatures);
                Console.WriteLine(JsonSerializer.Serialize(new { result.Suspicious, result.Score }));
                return 0;
            }

            Console.Error.WriteLine("extract <manifiesto.tsv> <características.tsv>");
            Console.Error.WriteLine("train <características.tsv> <directorio-nuevo>");
            Console.Error.WriteLine("assess <directorio-del-modelo> <sha256-revisado> <archivo>");
            return 2;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operación cancelada.");
            return 130;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }
}
