using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Win32;
using Newtonsoft.Json;
using System.Buffers.Text;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Media;
using System.Windows.Navigation;
using Wpf.Ui.Controls;
using static SpecterInsightKeygen.Models;
using static SpecterInsightKeygen.Utils;

namespace SpecterInsightKeygen;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : FluentWindow
{
    private byte[] _cipherText;
    private string _certFilePath;
    private X509Certificate2 _cert;
    public MainWindow()
    {
        InitializeComponent();
        this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        OutputText.Text= "Welcome to SpecterInsight C2 Keygen\n\nTo start, just follow these simple steps:\n- Input your name and email\n- Select your P12 Cert and input the password\n- Click the button \"GENERATE\"\n- Click save\n\nNOTES:\n- Please remember to replace \"Validator\" resource certificate in both SpecterInsight.Server.dll and SpecterInsight.UI.dll\n- The certificate that will go inside those files, MUST BE WITHOUT PASSWORD PROTECTION\n- Remember that applying a new license, will unlicense the tool. Be advised!";
    }

    private void Button_Click(object sender, RoutedEventArgs e)
    {
        if (EmailInput.Text.Length == 0 || NameInput.Text.Length == 0)
        {
            OutputText.Text = "Email or Name or Password are missing!!!";
        }
        else
        {
            try
            {
                _cert = new X509Certificate2(_certFilePath, CertPassBox.Password, X509KeyStorageFlags.EphemeralKeySet);

                LicenseValidationInfoEx licenseValidationInfoEx = new LicenseValidationInfoEx()
                {
                    ActivationsLeft = "999999",
                    CustomerEmail = EmailInput.Text,
                    CustomerName = NameInput.Text,
                    Expires = DateTime.Now.AddYears(100),
                    License = "valid",
                    ItemId = "1094",
                    ItemName = "Offsec",
                    LicenseLimit = "999999",
                    PaymentId = 1234,
                    PriceId = "1234567890",
                    Success = true,
                    SiteCount = "999999",
                    Key = LicenseKeyGenerate(_cert)
                };
                JsonSerializer serializer = new JsonSerializer();
                serializer.Formatting = Formatting.Indented;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (StreamWriter sw = new StreamWriter(ms))
                    {
                        serializer.Serialize(sw, licenseValidationInfoEx);
                    }
                    ms.Flush();
                    _cipherText = Encrypt(ms.ToArray(), "71eee87b4a514a7196cf10c42eae4af7");
                    OutputText.Text = $"Encrypted license:\n {(Convert.ToBase64String(_cipherText)).Substring(0, 20)+"..."}";
                }
            } catch (Exception ex)
            {
                OutputText.Text = ex.Message;
            }
        }

    }

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = e.Uri.AbsoluteUri,
            UseShellExecute = true  // Ensures it opens in the default browser
        });
        e.Handled = true;  // Prevents further handling
    }


    private void Button_Click_1(object sender, RoutedEventArgs e)
    {
        string defaultFileName = "license.json";
        string defaultPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); // User's home directory

        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            FileName = defaultFileName,         // Pre-fill filename
            InitialDirectory = defaultPath,     // Open user's home directory
            Filter = "JSON files (*.json)|*.json", // File filters
            Title = "Save License File"         // Dialog title
        };

        bool? result = saveFileDialog.ShowDialog();
        if (result == true)
        {
            string filePath = saveFileDialog.FileName;
            File.WriteAllBytes(filePath, _cipherText); // Example content
            OutputText.Text = $"License file succesfully saved to: {saveFileDialog.FileName}!\n\nNow just replace SpecterInsight's Certificate with yours and you're good to go!";
            SaveButton.Content = "FINISHED!";
            SaveButton.Background = Brushes.Green;
        }
        else
        {
            OutputText.Text = "\nOperation aborted!";
        }

    }

    private void Button_Click_2(object sender, RoutedEventArgs e)
    {

    }

    private void CertChooserButton_Click(object sender, RoutedEventArgs e)
    {
        string defaultPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); // User's home directory

        OpenFileDialog openFileDialog = new OpenFileDialog
        {
            InitialDirectory = defaultPath,     // Open user's home directory
            Filter = "Certificate File (*.p12)|*.p12", // File filters
            Title = "Open Certificate File"         // Dialog title
        };

        bool? result = openFileDialog.ShowDialog();
        if (result == true)
        {
            _certFilePath = openFileDialog.FileName; // Full certificate path
            OutputText.Text += $"\n\nSelected Certificate: {_certFilePath}";
        } else
        {
            OutputText.Text = "Certificate load aborted";

        }

    }
}