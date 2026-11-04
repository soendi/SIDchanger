using System.Windows;
using System.Windows.Controls;
using SidChanger.App.ViewModels;

namespace SidChanger.App;

/// <summary>Hauptfenster der Anwendung.</summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();

        _viewModel = new MainViewModel();
        DataContext = _viewModel;

        Loaded += async (_, _) => await _viewModel.InitializeAsync();
    }

    private void LogBox_OnTextChanged(object sender, TextChangedEventArgs e)
    {
        if (sender is TextBox box)
        {
            box.ScrollToEnd();
        }
    }
}
