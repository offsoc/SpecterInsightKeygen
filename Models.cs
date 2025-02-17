using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;

namespace SpecterInsightKeygen
{
    class Models
    {
        public class LicenseKey
        {
            // Token: 0x0600045A RID: 1114 RVA: 0x0000E431 File Offset: 0x0000C631
            public LicenseKey(byte[] data, byte[] signature)
            {
                this._data = data;
                this._signature = signature;
            }

            // Token: 0x0600045B RID: 1115 RVA: 0x0000E448 File Offset: 0x0000C648
            public static LicenseKey Parse(string serialized)
            {
                if (serialized.Length > 256)
                {
                    throw new FormatException("Invalid key length.");
                }
                byte[] array = WebEncoders.Base64UrlDecode(serialized);
                byte[] data = new byte[16];
                byte[] signature = new byte[array.Length - 16];
                Array.Copy(array, 0, data, 0, 16);
                Array.Copy(array, 16, signature, 0, signature.Length);
                return new LicenseKey(data, signature);
            }

            public static string Write(LicenseKey licenseKey)
            {
                byte[] array = new byte[16 + licenseKey._signature.Length];
                Array.Copy(licenseKey._data, 0, array, 0, 16);
                Array.Copy(licenseKey._signature, 16, array, 0, licenseKey._signature.Length);
                string serialized = WebEncoders.Base64UrlEncode(array);
                if (serialized.Length > 256)
                {
                    throw new FormatException("Invalid key length.");
                }

                return serialized;
            }

            // Token: 0x0600045C RID: 1116 RVA: 0x0000E4A8 File Offset: 0x0000C6A8
            public bool Validate(X509Certificate2 pkey)
            {
                bool flag;
                using (ECDsa ecdsa = pkey.GetECDsaPublicKey())
                {
                    flag = ecdsa.VerifyData(this._data, this._signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                }
                return flag;
            }

            public bool Sign(X509Certificate2 pkey)
            {
                int numbers;
                using (ECDsa ecdsa = pkey.GetECDsaPrivateKey())
                {
                    this._signature = ecdsa.SignData(this._data,HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                    if (this._signature.Length == 0)
                    {
                        return false;
                    } else
                    {
                        return true;
                    }
                }
            }

            // Token: 0x040001EA RID: 490
            public byte[] _data;

            // Token: 0x040001EB RID: 491
            public byte[] _signature;
        }

        public class LicenseValidationInfo
        {
            // Token: 0x1700011B RID: 283
            // (get) Token: 0x0600045D RID: 1117 RVA: 0x0000E4F4 File Offset: 0x0000C6F4
            // (set) Token: 0x0600045E RID: 1118 RVA: 0x0000E4FC File Offset: 0x0000C6FC
            [JsonProperty("success")]
            public bool Success { get; set; }

            // Token: 0x1700011C RID: 284
            // (get) Token: 0x0600045F RID: 1119 RVA: 0x0000E505 File Offset: 0x0000C705
            // (set) Token: 0x06000460 RID: 1120 RVA: 0x0000E50D File Offset: 0x0000C70D
            [JsonProperty("license")]
            public string License { get; set; }

            // Token: 0x1700011D RID: 285
            // (get) Token: 0x06000461 RID: 1121 RVA: 0x0000E516 File Offset: 0x0000C716
            // (set) Token: 0x06000462 RID: 1122 RVA: 0x0000E51E File Offset: 0x0000C71E
            [JsonProperty("item_id")]
            public string ItemId { get; set; }

            // Token: 0x1700011E RID: 286
            // (get) Token: 0x06000463 RID: 1123 RVA: 0x0000E527 File Offset: 0x0000C727
            // (set) Token: 0x06000464 RID: 1124 RVA: 0x0000E52F File Offset: 0x0000C72F
            [JsonProperty("item_name")]
            public string ItemName { get; set; }

            // Token: 0x1700011F RID: 287
            // (get) Token: 0x06000465 RID: 1125 RVA: 0x0000E538 File Offset: 0x0000C738
            // (set) Token: 0x06000466 RID: 1126 RVA: 0x0000E540 File Offset: 0x0000C740
            [JsonProperty("checksum")]
            public string Checksum { get; set; }

            // Token: 0x17000120 RID: 288
            // (get) Token: 0x06000467 RID: 1127 RVA: 0x0000E549 File Offset: 0x0000C749
            // (set) Token: 0x06000468 RID: 1128 RVA: 0x0000E551 File Offset: 0x0000C751
            [JsonProperty("expires")]
            public DateTime Expires { get; set; }

            // Token: 0x17000121 RID: 289
            // (get) Token: 0x06000469 RID: 1129 RVA: 0x0000E55A File Offset: 0x0000C75A
            // (set) Token: 0x0600046A RID: 1130 RVA: 0x0000E562 File Offset: 0x0000C762
            [JsonProperty("payment_id")]
            public int PaymentId { get; set; }

            // Token: 0x17000122 RID: 290
            // (get) Token: 0x0600046B RID: 1131 RVA: 0x0000E56B File Offset: 0x0000C76B
            // (set) Token: 0x0600046C RID: 1132 RVA: 0x0000E573 File Offset: 0x0000C773
            [JsonProperty("customer_name")]
            public string CustomerName { get; set; }

            // Token: 0x17000123 RID: 291
            // (get) Token: 0x0600046D RID: 1133 RVA: 0x0000E57C File Offset: 0x0000C77C
            // (set) Token: 0x0600046E RID: 1134 RVA: 0x0000E584 File Offset: 0x0000C784
            [JsonProperty("customer_email")]
            public string CustomerEmail { get; set; }

            // Token: 0x17000124 RID: 292
            // (get) Token: 0x0600046F RID: 1135 RVA: 0x0000E58D File Offset: 0x0000C78D
            // (set) Token: 0x06000470 RID: 1136 RVA: 0x0000E595 File Offset: 0x0000C795
            [JsonProperty("license_limit")]
            public string LicenseLimit { get; set; }

            // Token: 0x17000125 RID: 293
            // (get) Token: 0x06000471 RID: 1137 RVA: 0x0000E59E File Offset: 0x0000C79E
            // (set) Token: 0x06000472 RID: 1138 RVA: 0x0000E5A6 File Offset: 0x0000C7A6
            [JsonProperty("site_count")]
            public string SiteCount { get; set; }

            // Token: 0x17000126 RID: 294
            // (get) Token: 0x06000473 RID: 1139 RVA: 0x0000E5AF File Offset: 0x0000C7AF
            // (set) Token: 0x06000474 RID: 1140 RVA: 0x0000E5B7 File Offset: 0x0000C7B7
            [JsonProperty("activations_left")]
            public string ActivationsLeft { get; set; }

            // Token: 0x17000127 RID: 295
            // (get) Token: 0x06000475 RID: 1141 RVA: 0x0000E5C0 File Offset: 0x0000C7C0
            // (set) Token: 0x06000476 RID: 1142 RVA: 0x0000E5C8 File Offset: 0x0000C7C8
            [JsonProperty("price_id")]
            public string PriceId { get; set; }

            // Token: 0x06000477 RID: 1143 RVA: 0x0000E5D1 File Offset: 0x0000C7D1
            public bool Validate(string email)
            {
                return this.Success && this.CustomerEmail.Equals(email, StringComparison.InvariantCultureIgnoreCase) && DateTime.Now < this.Expires;
            }
        }

        public class LicenseValidationInfoEx : LicenseValidationInfo
        {
            // Token: 0x17000128 RID: 296
            // (get) Token: 0x06000479 RID: 1145 RVA: 0x0000E604 File Offset: 0x0000C804
            // (set) Token: 0x0600047A RID: 1146 RVA: 0x0000E60C File Offset: 0x0000C80C
            [JsonProperty("key")]
            public string Key { get; set; }

            // Token: 0x0600047B RID: 1147 RVA: 0x0000E615 File Offset: 0x0000C815
            public LicenseValidationInfoEx()
            {
            }

            // Token: 0x0600047C RID: 1148 RVA: 0x0000E620 File Offset: 0x0000C820
            public LicenseValidationInfoEx(LicenseValidationInfo info, string key)
            {
                base.PriceId = info.PriceId;
                base.PaymentId = info.PaymentId;
                base.Success = info.Success;
                base.LicenseLimit = info.LicenseLimit;
                base.License = info.License;
                base.ActivationsLeft = info.ActivationsLeft;
                base.Checksum = info.Checksum;
                base.CustomerEmail = info.CustomerEmail;
                base.CustomerName = info.CustomerName;
                base.Expires = info.Expires;
                base.ItemId = info.ItemId;
                base.ItemName = info.ItemName;
                this.Key = key;
            }
        }
    }
}
