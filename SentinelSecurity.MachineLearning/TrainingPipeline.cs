using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.ML;
using SentinelSecurity.Engine;

namespace SentinelSecurity.MachineLearning;

public sealed record Evaluation(int TruePositive, int FalsePositive, int TrueNegative, int FalseNegative,
    double Accuracy, double? Precision, double Recall, double F1, double FalsePositiveRate, double FalseNegativeRate);

public sealed record TrainingReport(int SchemaVersion, string ModelSha256, DateTimeOffset CreatedAt,
    int TrainingRows, Evaluation Validation, Evaluation Test, int TrainingIterations);

public static class TrainingPipeline
{
    internal const string ModelFileName = "modelo.zip";
    internal const string ReportFileName = "evaluacion.json";

    public static async Task<TrainingReport> TrainAsync(string featuresPath, string output, CancellationToken ct)
    {
        var data = await FeatureDataset.LoadAsync(featuresPath, ct);
        var ml = new MLContext(seed: 42);
        var train = ml.Data.LoadFromEnumerable(data["train"]);
        var validation = ml.Data.LoadFromEnumerable(data["validation"]);
        var test = ml.Data.LoadFromEnumerable(data["test"]);
        ITransformer? selected = null;
        Evaluation? validationMetrics = null;
        var selectedIterations = 0;

        foreach (var iterations in new[] { 20, 60 })
        {
            ct.ThrowIfCancellationRequested();
            var pipeline = ml.Transforms.NormalizeMeanVariance("NormalizedFeatures", nameof(ModelInput.Features))
                .Append(ml.BinaryClassification.Trainers.SdcaLogisticRegression(nameof(ModelInput.Label),
                    "NormalizedFeatures", maximumNumberOfIterations: iterations));
            var model = pipeline.Fit(train);
            var metrics = Evaluate(ml, model.Transform(validation), ct);
            if (validationMetrics is null || metrics.F1 > validationMetrics.F1)
            {
                selected = model;
                validationMetrics = metrics;
                selectedIterations = iterations;
            }
        }

        var testMetrics = Evaluate(ml, selected!.Transform(test), ct);
        var destination = Path.GetFullPath(output);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("Seleccione un directorio de salida nuevo.");

        var staging = destination + $".{Guid.NewGuid():N}.tmp";
        Directory.CreateDirectory(staging);
        try
        {
            var modelPath = Path.Combine(staging, ModelFileName);
            ml.Model.Save(selected, train.Schema, modelPath);
            await using var modelStream = File.OpenRead(modelPath);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(modelStream, ct));
            var report = new TrainingReport(FeatureDataset.SchemaVersion, hash, DateTimeOffset.UtcNow, data["train"].Count,
                validationMetrics!, testMetrics, selectedIterations);
            await File.WriteAllTextAsync(Path.Combine(staging, ReportFileName), JsonSerializer.Serialize(report,
                new JsonSerializerOptions { WriteIndented = true }), ct);
            await modelStream.DisposeAsync();
            ct.ThrowIfCancellationRequested();
            Directory.Move(staging, destination);
            return report;
        }
        finally
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
    }

    private static Evaluation Evaluate(MLContext ml, IDataView data, CancellationToken ct)
    {
        var tp = 0;
        var fp = 0;
        var tn = 0;
        var fn = 0;
        foreach (var result in ml.Data.CreateEnumerable<ModelOutput>(data, reuseRowObject: true))
        {
            ct.ThrowIfCancellationRequested();
            if (result.Label && result.PredictedLabel) tp++;
            else if (result.PredictedLabel) fp++;
            else if (result.Label) fn++;
            else tn++;
        }

        return new Evaluation(tp, fp, tn, fn,
            (double)(tp + tn) / (tp + tn + fp + fn), tp + fp == 0 ? null : (double)tp / (tp + fp),
            (double)tp / (tp + fn), (2d * tp) / (2 * tp + fp + fn), (double)fp / (fp + tn), (double)fn / (fn + tp));
    }
}

public sealed class ReviewedModel
{
    private readonly MLContext ml;
    private readonly ITransformer model;

    private ReviewedModel(MLContext ml, ITransformer model, TrainingReport report)
    {
        this.ml = ml;
        this.model = model;
        Report = report;
    }

    public TrainingReport Report { get; }

    public static async Task<ReviewedModel> LoadAsync(string bundle, string reviewedSha256, CancellationToken ct)
    {
        var reportPath = Path.Combine(bundle, TrainingPipeline.ReportFileName);
        var modelPath = Path.Combine(bundle, TrainingPipeline.ModelFileName);
        await using var reportStream = File.OpenRead(reportPath);
        if (reportStream.Length is <= 0 or > 64 * 1024) throw new InvalidDataException("El informe tiene un tamaño inválido.");
        var report = await JsonSerializer.DeserializeAsync<TrainingReport>(reportStream, cancellationToken: ct);
        if (report is null || report.SchemaVersion != FeatureDataset.SchemaVersion || report.Validation is null || report.Test is null)
            throw new InvalidDataException("El informe no corresponde al esquema de características.");

        await using var stream = File.OpenRead(modelPath);
        if (stream.Length is <= 0 or > 32 * 1024 * 1024) throw new InvalidDataException("El modelo tiene un tamaño inválido.");
        var digest = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
        if (!digest.Equals(report.ModelSha256, StringComparison.OrdinalIgnoreCase) ||
            !digest.Equals(reviewedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("El modelo no coincide con el SHA-256 revisado.");

        stream.Position = 0;
        var ml = new MLContext(seed: 42);
        var model = ml.Model.Load(stream, out _);
        return new ReviewedModel(ml, model, report);
    }

    public (bool Suspicious, float Score) Assess(FileFeatures features)
    {
        var sample = new ModelInput { Features = FeatureDataset.ToVector(features) };
        var data = ml.Data.LoadFromEnumerable(new[] { sample });
        var result = ml.Data.CreateEnumerable<ModelOutput>(model.Transform(data), reuseRowObject: false).Single();
        return (result.PredictedLabel, result.Score);
    }
}
