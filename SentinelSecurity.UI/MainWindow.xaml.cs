using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Threading;

namespace SentinelSecurity.UI;

public partial class MainWindow : Window
{
    private const int ImmersiveDarkMode = 20;

    private static readonly DependencyProperty UseLightThemeProperty = DependencyProperty.Register(
        "UseLightTheme",
        typeof(bool),
        typeof(MainWindow),
        new PropertyMetadata(false, OnThemeChanged));

    public MainWindow()
    {
        InitializeComponent();
        SetBinding(UseLightThemeProperty, new Binding("LightTheme"));
        SourceInitialized += (_, _) => ApplyTitleBarTheme((bool)GetValue(UseLightThemeProperty));
    }

    private static void OnThemeChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        var window = (MainWindow)sender;
        var light = (bool)args.NewValue;
        var palettes = Application.Current.Resources.MergedDictionaries;
        var nextPalette = light ? "Resources/Light.xaml" : "Resources/Dark.xaml";
        if (!palettes[0].Source.OriginalString.EndsWith(nextPalette, StringComparison.Ordinal))
        {
            palettes[0] = new ResourceDictionary { Source = new Uri(nextPalette, UriKind.Relative) };
        }

        window.ApplyTitleBarTheme(light);
    }

    private void ApplyTitleBarTheme(bool light)
    {
        var handle = new WindowInteropHelper(this).Handle;
        if (handle == IntPtr.Zero)
        {
            return;
        }

        var dark = light ? 0 : 1;
        _ = DwmSetWindowAttribute(handle, ImmersiveDarkMode, ref dark, sizeof(int));
    }

    private void OnIntelligentClick(object sender, RoutedEventArgs args)
    {
        _ = Dispatcher.InvokeAsync(() => IntelligentPanel.BringIntoView(), DispatcherPriority.Loaded);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int valueSize);
}
