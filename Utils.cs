using Microsoft.AspNetCore.WebUtilities;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using static SpecterInsightKeygen.Models;

namespace SpecterInsightKeygen
{
    public class Utils
    {

        public const string DEFAULT_PASSWORD = "5e16e53245c147a8acd1b3e38de0135d";

        // Token: 0x04000063 RID: 99
        public static byte[] SALT = new byte[] { 251, 51, 164, 251, 59, 131, 182, 228 };

        // Token: 0x04000064 RID: 100
        public static readonly byte[] MARKER = new byte[]
        {
            89, 37, 32, 212, 143, 199, 216, 38, 176, 236,
            164, 32, 184, 202, 182
        };

        public static string LicenseKeyGenerate(X509Certificate2 _cert)
        {
            byte[] data = new byte[16];  // The required 16-byte data segment

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(data);      // Fill data with random bytes
            }

            Models.LicenseKey licenseKey = new Models.LicenseKey(data, null);
            if (!licenseKey.Sign(_cert))
            {
                throw new Exception("License signin failed!");
            }
            
            // Combine data + signature
            byte[] combined = new byte[licenseKey._data.Length + licenseKey._signature.Length];
            Array.Copy(licenseKey._data, 0, combined, 0, data.Length);
            Array.Copy(licenseKey._signature, 0, combined, data.Length, licenseKey._signature.Length);

            // Base64 URL encode the result
            return WebEncoders.Base64UrlEncode(combined);
        }

        public static byte[] Encrypt(byte[] plaintextbytes, string password = "5e16e53245c147a8acd1b3e38de0135d")
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, Utils.SALT);
            byte[] array;
            using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
            {
                aesCryptoServiceProvider.KeySize = 256;
                aesCryptoServiceProvider.BlockSize = 128;
                aesCryptoServiceProvider.Key = rfc2898DeriveBytes.GetBytes(aesCryptoServiceProvider.KeySize / 8);
                aesCryptoServiceProvider.GenerateIV();
                ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateEncryptor(aesCryptoServiceProvider.Key, aesCryptoServiceProvider.IV);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(aesCryptoServiceProvider.IV, 0, aesCryptoServiceProvider.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(Utils.MARKER, 0, Utils.MARKER.Length);
                        cryptoStream.Write(plaintextbytes, 0, plaintextbytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    array = memoryStream.ToArray();
                }
            }
            return array;
        }

        // Token: 0x04000065 RID: 101
        private static readonly Regex PATH_REGEX = new Regex("^(?:[a-z]:|\\\\\\\\[a-z0-9_.$●-]+\\\\[a-z0-9_.$●-]+)\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        public static byte[] Decrypt(byte[] ciphertextbytes, string password = "5e16e53245c147a8acd1b3e38de0135d")
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, Utils.SALT);
            byte[] array6;
            using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
            {
                aesCryptoServiceProvider.KeySize = 256;
                aesCryptoServiceProvider.BlockSize = 128;
                aesCryptoServiceProvider.Key = rfc2898DeriveBytes.GetBytes(aesCryptoServiceProvider.KeySize / 8);
                byte[] array = new byte[16];
                Array.Copy(ciphertextbytes, array, array.Length);
                aesCryptoServiceProvider.IV = array;
                ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateDecryptor(aesCryptoServiceProvider.Key, aesCryptoServiceProvider.IV);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (MemoryStream memoryStream2 = new MemoryStream(ciphertextbytes))
                    {
                        byte[] array2 = new byte[4096];
                        memoryStream2.Read(array2, 0, 16);
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream2, cryptoTransform, CryptoStreamMode.Read))
                        {
                            int num;
                            while ((num = cryptoStream.Read(array2, 0, array2.Length)) > 0)
                            {
                                memoryStream.Write(array2, 0, num);
                            }
                        }
                        byte[] array3 = memoryStream.ToArray();
                        byte[] array4 = new byte[Utils.MARKER.Length];
                        Array.Copy(array3, array4, array4.Length);
                        if (!array4.SequenceEqual(Utils.MARKER))
                        {
                            throw new Exception("File is not using a supported encryption format.");
                        }
                        byte[] array5 = new byte[array3.Length - array4.Length];
                        Array.Copy(array3, array4.Length, array5, 0, array5.Length);
                        array6 = array5;
                    }
                }
            }
            return array6;
        }
    }
}
