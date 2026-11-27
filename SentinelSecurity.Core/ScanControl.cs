namespace SentinelSecurity.Core;

public sealed class ScanControl
{
    private readonly object gate = new();
    private TaskCompletionSource? resumeSignal;
    public Guid Id { get; } = Guid.NewGuid();

    public bool IsPaused
    {
        get { lock (gate) return resumeSignal is not null; }
    }

    public void Pause()
    {
        lock (gate)
            resumeSignal ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public void Resume()
    {
        lock (gate)
        {
            resumeSignal?.TrySetResult();
            resumeSignal = null;
        }
    }

    public Task WaitAsync(CancellationToken ct)
    {
        lock (gate)
        {
            ct.ThrowIfCancellationRequested();
            return resumeSignal?.Task.WaitAsync(ct) ?? Task.CompletedTask;
        }
    }
}
