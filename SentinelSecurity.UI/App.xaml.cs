using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Markup;
using SentinelSecurity.Engine;
using SentinelSecurity.Infrastructure;

namespace SentinelSecurity.UI;

public partial class App : Application
{
    private Mutex? instance;
    private bool ownsInstance;
    private ShellViewModel? viewModel;
    private bool closing;
    private bool shutdownRequested;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("es-CL");
        FrameworkElement.LanguageProperty.OverrideMetadata(typeof(FrameworkElement),
            new FrameworkPropertyMetadata(XmlLanguage.GetLanguage("es-CL")));

        try
        {
            instance = new Mutex(true, @"Local\SentinelSecurity-" + Environment.UserName, out ownsInstance);
            if (!ownsInstance)
            {
                MessageBox.Show("Sentinel Security ya se está ejecutando en esta sesión.", "Sentinel Security");
                Shutdown();
                return;
            }
            var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SentinelSecurity");
            var store = new SqliteStore(data);
            await store.InitializeAsync(CancellationToken.None);
            var engine = new ScanEngine(store);
            viewModel = new ShellViewModel(store, engine, new QuarantineService(store, data), data, Dispatcher);
            var window = new MainWindow { DataContext = viewModel };
            MainWindow = window;
            window.Closing += OnWindowClosing;
            window.Show();
            await viewModel.InitializeAsync();
        }
        catch (Exception error)
        {
            MessageBox.Show("No se pudo iniciar Sentinel Security.\n" + error.Message, "Sentinel Security",
                MessageBoxButton.OK, MessageBoxImage.Error);
            if (viewModel is not null)
                await viewModel.DisposeAsync();
            Shutdown(1);
        }
    }

    private async void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        if (closing)
            return;
        e.Cancel = true;
        if (viewModel is null || shutdownRequested)
            return;
        shutdownRequested = true;
        if (sender is Window window)
            window.IsEnabled = false;
        try { await viewModel.DisposeAsync(); }
        catch (Exception error) { System.Diagnostics.Trace.TraceError(error.ToString()); }
        closing = true;
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (ownsInstance)
            instance?.ReleaseMutex();
        instance?.Dispose();
        base.OnExit(e);
    }
}
