using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;

namespace LoginManager
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const string registryPath = @"/Software/DianaLoginManager";
        public MainWindow()
        {
            InitializeComponent();

            this.Loaded += (s, e) =>
            {
                var reg = Registry.CurrentUser.OpenSubKey(registryPath);
                if (reg == null)
                {
                    InputBox.Visibility = Visibility.Visible;
                }               
            };

            registryButton.Click += (s, e) =>
            {

                var reg = Registry.CurrentUser.OpenSubKey(registryPath, true);
                if (reg == null) reg = Registry.CurrentUser.CreateSubKey(registryPath, true);
                reg.SetValue("password", HashPassword(InputTextBox.Password));
                InputBox.Visibility = Visibility.Hidden;
                reg.Close();
            };
            cancelButton.Click += (s, e) => { this.Close(); };


            loginButton.Click += (s, e) =>
            {
                var reg = Registry.CurrentUser.OpenSubKey(registryPath);
                if (reg == null)
                {
                    InputBox.Visibility = Visibility.Visible;
                    reg.Close();
                    return;
                }
                if (VerifyHashedPassword(reg.GetValue("password").ToString(), passwordTextBox.Password))
                {
                    StartupBox.Visibility = Visibility.Visible;
                }
                else
                {
                    MessageBox.Show("Неверный пароль!", "Ошибка!",MessageBoxButton.OK,MessageBoxImage.Error);
                }
                reg.Close();
            };

            exitButton.Click += (s, e) => { this.Close(); };

            startButton.Click += (s, e) =>
            {
                File.WriteAllBytes($"{System.IO.Path.GetTempPath()}Diana.exe", Properties.Resources.Diana_2);
                Process.Start($"{System.IO.Path.GetTempPath()}Diana.exe");
                this.Close();
            };

            changePasswordButton.Click += (s, e) =>
            {
                InputBox.Visibility = Visibility.Visible;
                helloTextBlock.Visibility = Visibility.Hidden;
                StartupBox.Visibility = Visibility.Hidden;
            };
        }
        
        public static string HashPassword(string password)
        {
            byte[] salt;
            byte[] buffer2;
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, 0x10, 0x3e8))
            {
                salt = bytes.Salt;
                buffer2 = bytes.GetBytes(0x20);
            }
            byte[] dst = new byte[0x31];
            Buffer.BlockCopy(salt, 0, dst, 1, 0x10);
            Buffer.BlockCopy(buffer2, 0, dst, 0x11, 0x20);

            
            return Convert.ToBase64String(dst);
        }

        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            byte[] buffer4;
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            byte[] src = Convert.FromBase64String(hashedPassword);
            if ((src.Length != 0x31) || (src[0] != 0))
            {
                return false;
            }
            byte[] dst = new byte[0x10];
            Buffer.BlockCopy(src, 1, dst, 0, 0x10);
            byte[] buffer3 = new byte[0x20];
            Buffer.BlockCopy(src, 0x11, buffer3, 0, 0x20);
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, dst, 0x3e8))
            {
                buffer4 = bytes.GetBytes(0x20);
            }
            return ByteArraysEqual(buffer3, buffer4);
        }

        private static bool ByteArraysEqual(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length) return false;
            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i]) return false;
            }
            return true;
        }
    }
}
