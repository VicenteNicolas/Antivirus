using System.Windows.Input;

namespace SentinelSecurity.UI;

internal sealed class UiCommand(Action<object?> execute, Func<bool>? enabled = null) : ICommand
{
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => enabled?.Invoke() != false;
    public void Execute(object? parameter) => execute(parameter);
}
