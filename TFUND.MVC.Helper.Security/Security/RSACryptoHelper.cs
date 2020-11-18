using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TFUND.MVC.Helper.Security
{
    public class RSACryptoHelper
    {
        public enum RSAKeySize
        {
            Key512 = 512,
            Key1024 = 1024,
            Key2048 = 2048,
            Key4096 = 4096
        }

        /// <summary>
        /// RSA Encrypt & Decrypt
        /*
         *  // Get Key
            string PublicKey = "MjA0OCE8UlNBS2V5VmFsdWU+PE1vZHVsdXM+clB2NnRoOXlFZEs3YXNXOGNZUW9YakhZLzFjT0VtdE0rajNudnZzL0NicEhOeVJxWjB2TXUvVzNrbG5kVExVVUZGbEZsSlVXVnZ0Mmo4N3lOZTY2alNvVnNPZkRIc0lINGJ2bkZLUjRFck5yY1hNUThOb1JxeVdIbTVYWmgrOWFzV0UrcEY3YXBOc0M2OGxuSWc1UDk4elEvYUY1cWw4UU1zTkRnUmRzTVYyVzlxa1ZuQ3AyUG03QVNIVkUrNjRiQkJkK21CSHRjSi9MNTRBRkh6SFprWGh5TFBuaFRPNzkyemt2VTUySTZaNGFjZE9OZkRZQVo2ZVVvQ2tmU3ZsSDlsQytVcVFXYU42bWF2N29Fdk42alVPRDZNSDlsN0pVVlJRS2loaHRWQkFlY1lXWTNmN05JNERJRjcrYm9ybnhzMko0U3IvOXVQM0NIeXk3d3laUG1RPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+";
            string PrivateKey = "MjA0OCE8UlNBS2V5VmFsdWU+PE1vZHVsdXM+clB2NnRoOXlFZEs3YXNXOGNZUW9YakhZLzFjT0VtdE0rajNudnZzL0NicEhOeVJxWjB2TXUvVzNrbG5kVExVVUZGbEZsSlVXVnZ0Mmo4N3lOZTY2alNvVnNPZkRIc0lINGJ2bkZLUjRFck5yY1hNUThOb1JxeVdIbTVYWmgrOWFzV0UrcEY3YXBOc0M2OGxuSWc1UDk4elEvYUY1cWw4UU1zTkRnUmRzTVYyVzlxa1ZuQ3AyUG03QVNIVkUrNjRiQkJkK21CSHRjSi9MNTRBRkh6SFprWGh5TFBuaFRPNzkyemt2VTUySTZaNGFjZE9OZkRZQVo2ZVVvQ2tmU3ZsSDlsQytVcVFXYU42bWF2N29Fdk42alVPRDZNSDlsN0pVVlJRS2loaHRWQkFlY1lXWTNmN05JNERJRjcrYm9ybnhzMko0U3IvOXVQM0NIeXk3d3laUG1RPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPnpFanZuczN2di9hTWU3LzVXYUE4aWJwQkxmYmhUUXJMa05TNUMxNVI5Y24rMXU5YWxXL1JCb3c5RW5nWSs2U2w0end6dTNyRUNKZERadTZpSVd5YnBEMXZQMXFRMExRb0Q4YS9YUXhHTHlRQWkvbEk0dW5Zd2R5ck1UQm1qWEVPSXRROVFHWE1PY0hmNUJKUHdYYmJBb0tQY29uMVVQUXpxSnZVMGhodS90cz08L1A+PFE+Mk1hTWdQZFBpcmZNck8rdGY2MjJVU2FpeDl3eXRHNDRDTEx1Yzd0WGRLQno3VTJzbU1zQlFETTA4ekEvWlJUeW9HMlA5c01kRDhidTRHZGdldWt5Q241R0tyckxnd1ZNaEJvSHZTYzg2aWM3UmVqY3kzbXpBVnlyRE9QTjJpZGNuRURla2YzelE1KzRGbG0wQ0F4dUNzdmQ1d2pYRXF0U1E0cTN5VmhEVTVzPTwvUT48RFA+ZnU1ZXZTeTJhRzk0TUxoQzVmYVRSdnlNM1ZPR0FFblIzS2JnWjNqdXNpc1ZobFZvMG11TTFHVzAyTkg0cS90TSs5bC9SMkZyaHU3OStXb1RJWE9MYmN5aVlCb1UyeWpscjQvTmZiSlB0YURJR2pFRm9jQ3RaeCtHMjJSNGhEQVlHWG9JcVFmWGtwZXRWdGd0NkViQ3BGZWRiQXplZWJPU21aUmg4ejB0VW5zPTwvRFA+PERRPkNSNkpLSisreStJaGpTRGtGcHZ6TUlURWtrM1VJRDBHeEc3cWt4bk5ldzJJOHZHeWtoYndMWWc1OFFVVmxhWUU4dlRJK3FPSXBISkUrRkhCQUVxeEhUbmtyOFY5N0R3YjFPN1hab0N4RWxTbUxMRzRJQ00xZ1pncFpmaHJYNE1LWlZSaFNKajdVOXZ6UFpWMmVtUXplT2JNcGZ4OE43L1hUUm9YMHpPUVdZTT08L0RRPjxJbnZlcnNlUT5CQzlVRWVrTEtWRkRnRmpUVi9QZzdBS3NnOHplUjJKeXJ6aUtMUTlEUEdJS3UyU2JsNHBEWHUzSTJDanpNUDdmUVFmeTJndFVUaXQrYXhRNGVJd3JJTXFuOW44UW1mRWE0bTRKUjQ0akNKaXh4NE9DZHQ3cTVMY3Z3U2psOFljVXhqdzZyVnhnRnlHdXlTYmZMWWlmcVpOOFA0MlhBcXh1M2Z6THE4M1lseVE9PC9JbnZlcnNlUT48RD5wVW1jTkx0MVJueUNZaktRcmpMbVU2THp3bi9QVFdCRHpIU3NaSHN6cjdyVFkyZ2pWNUpCRFhSck5LY3pZcUUvajNZQm0waWRjUDJVT3pNMWtyMEtlZW8xa2JUU1p5aGxXWmN1NVRXR0dmQmdnS1cvRVRSOVgzaGJ6Qmx5SW9aZHRWSERCbEl3UHdlYUVleCs1RGFpeUpkbk5vSTllOEtiK3JWRFlpMGNUMG1ZcWhqMnlxWXBHT0xZMk1TY2RRT1A5RkxBbytJd3Y0YjdSMFBnUTVjckJqRlNFdzFuZDY0Q2RNTm9HR1BiVTQ5emxMUTUvS1FxbHljRGRBKzZZRU9KaFV0NFFabTQ5OTIxMjJZWkRDQVlmbnhWNmlVZk5TaUl6T1lkWUtSQnFod0pNNGRLZy9MTTVlN3AzdWQzamwxVGp2ZjhveTVjRjJ1L0EzTVZqMU9QRlE9PTwvRD48L1JTQUtleVZhbHVlPg==";
            // =========================
            // Set Key
            var rsa = new RSACryptoHelper.RSACryptoGenerator(PublicKey, PrivateKey);
            RSACryptoHelper.RSACryptoUtil.SetContainer(rsa);
            // ==========================

            var encryptValue = RSACryptoHelper.RSACryptoUtil.EncryptData("encrypt password");

            var result = RSACryptoHelper.RSACryptoUtil.DecryptData(encryptValue);
        */
        /// </summary>
        public static class RSACryptoUtil
        {
            public static RSACryptoGenerator RSA;
            public static string KeyPublish;
            public static string KeyPrivate;
            public static string KeyName;

            private static bool _optimalAsymmetricEncryptionPadding = false;
            public static void SetContainer(RSACryptoGenerator rsa)
            {
                RSA = rsa;
                KeyPublish = RSA.KeyPublish; // false to get the public key   
                KeyPrivate = RSA.KeyPrivate; // true to get the private key   
                KeyName = RSA.KeyName;
            }

            public static string EncryptData(string text)
            {
                int keySize = 0;
                string publicKeyXml = "";

                GetKeyFromEncryptionString(KeyPublish, out keySize, out publicKeyXml);

                var encrypted = Encrypt(Encoding.UTF8.GetBytes(text), keySize, publicKeyXml);

                return Convert.ToBase64String(encrypted);
            }

            private static byte[] Encrypt(byte[] data, int keySize, string publicKeyXml)
            {
                if (data == null || data.Length == 0) throw new ArgumentException("Data are empty", "data");
                int maxLength = GetMaxDataLength(keySize);
                if (data.Length > maxLength) throw new ArgumentException(String.Format("Maximum data length is {0}", maxLength), "data");
                if (!IsKeySizeValid(keySize)) throw new ArgumentException("Key size is not valid", "keySize");
                if (String.IsNullOrEmpty(publicKeyXml)) throw new ArgumentException("Key is null or empty", "publicKeyXml");

                var parameters = new CspParameters
                {
                    ProviderType = 1, // PROV_RSA_FULL
                    KeyContainerName = KeyName
                };
                using (var provider = new RSACryptoServiceProvider(parameters))
                {
                    provider.FromXmlString(publicKeyXml);
                    return provider.Encrypt(data, _optimalAsymmetricEncryptionPadding);
                }
            }


            public static string DecryptData(string dataToDecrypt)
            {
                int keySize = 0;
                string publicAndPrivateKeyXml = "";

                GetKeyFromEncryptionString(KeyPrivate, out keySize, out publicAndPrivateKeyXml);

                var decrypted = Decrypt(Convert.FromBase64String(dataToDecrypt), keySize, publicAndPrivateKeyXml);

                return Encoding.UTF8.GetString(decrypted);
            }

            private static byte[] Decrypt(byte[] data, int keySize, string publicAndPrivateKeyXml)
            {
                if (data == null || data.Length == 0) throw new ArgumentException("Data are empty", "data");
                if (!IsKeySizeValid(keySize)) throw new ArgumentException("Key size is not valid", "keySize");
                if (String.IsNullOrEmpty(publicAndPrivateKeyXml)) throw new ArgumentException("Key is null or empty", "publicAndPrivateKeyXml");

                var parameters = new CspParameters
                {
                    ProviderType = 1, // PROV_RSA_FULL
                    KeyContainerName = KeyName
                };
                using (var provider = new RSACryptoServiceProvider(parameters))
                {
                    provider.FromXmlString(publicAndPrivateKeyXml);
                    return provider.Decrypt(data, _optimalAsymmetricEncryptionPadding);
                }
            }
            
            #region Helper
            private static int GetMaxDataLength(int keySize)
            {
                if (_optimalAsymmetricEncryptionPadding)
                {
                    return ((keySize - 384) / 8) + 7;
                }
                return ((keySize - 384) / 8) + 37;
            }

            private static bool IsKeySizeValid(int keySize)
            {
                return keySize >= 384 && keySize <= 16384 && keySize % 8 == 0;
            }

            private static void GetKeyFromEncryptionString(string rawkey, out int keySize, out string xmlKey)
            {
                keySize = 0;
                xmlKey = "";

                if (rawkey != null && rawkey.Length > 0)
                {
                    byte[] keyBytes = Convert.FromBase64String(rawkey);
                    var stringKey = Encoding.UTF8.GetString(keyBytes);

                    if (stringKey.Contains("!"))
                    {
                        var splittedValues = stringKey.Split(new char[] { '!' }, 2);

                        try
                        {
                            keySize = int.Parse(splittedValues[0]);
                            xmlKey = splittedValues[1];
                        }
                        catch (Exception e) { }
                    }
                }
            }
            #endregion
        }

        /// <summary>
        /// RSA KeyGenerater
        /*
            // generate key
            RSACryptoHelper.RSACryptoGenerator key = new RSACryptoHelper.RSACryptoGenerator("KeyEncode", RSACryptoHelper.RSAKeySize.Key2048);
            string PublicKey = key.KeyPublish;
            string PrivateKey = key.KeyPrivate;
            // =========================
         */
        /// </summary>
        public class RSACryptoGenerator
        {
            public string KeyPublish { get; set; }
            public string KeyPrivate { get; set; }
            public string KeyName { get; set; }

            public RSACryptoGenerator(string keyName="KeyEncode", RSAKeySize rsaKeySize = RSAKeySize.Key2048)
            {
                // Create the CspParameters object and set the key container
                // name used to store the RSA key pair.
                KeyName = keyName;
                var parameters = new CspParameters
                {
                    ProviderType=1, // PROV_RSA_FULL
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int)KeyNumber.Exchange,
                    KeyContainerName = KeyName
                };

                int keySize = (int)rsaKeySize;
                if (keySize % 2 != 0 || keySize < 512)
                    throw new Exception("Key should be multiple of two and greater than 512.");

                var rsa = new RSACryptoServiceProvider(keySize, parameters);

                var publicKey = rsa.ToXmlString(false);
                var privateKey = rsa.ToXmlString(true);

                var publicKeyWithSize = IncludeKeyInEncryptionString(publicKey, keySize);
                var privateKeyWithSize = IncludeKeyInEncryptionString(privateKey, keySize);

                // set key 
                KeyPublish = publicKeyWithSize; // false to get the public key   
                KeyPrivate = privateKeyWithSize; // true to get the private key   
            }


            public RSACryptoGenerator(string publicKey, string privateKey, string keyName = "KeyEncode")
            {
                KeyPublish = publicKey;
                KeyPrivate = privateKey;
                KeyName = keyName;
            }

            public void ChangeKey(string keyName = "KeyEncode", RSAKeySize rsaKeySize = RSAKeySize.Key2048)
            {

                // Create the CspParameters object and set the key container
                // name used to store the RSA key pair.
                KeyName = keyName;
                var parameters = new CspParameters
                {
                    ProviderType = 1, // PROV_RSA_FULL
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int)KeyNumber.Exchange,
                    KeyContainerName = KeyName
                };

                int keySize = (int)rsaKeySize;
                if (keySize % 2 != 0 || keySize < 512)
                    throw new Exception("Key should be multiple of two and greater than 512.");

                var rsa = new RSACryptoServiceProvider(keySize, parameters);

                //KeyPublish = rsa.ToXmlString(false); // false to get the public key   
                //KeyPrivate = rsa.ToXmlString(true); // true to get the private key   

                var publicKey = rsa.ToXmlString(false);
                var privateKey = rsa.ToXmlString(true);

                var publicKeyWithSize = IncludeKeyInEncryptionString(publicKey, keySize);
                var privateKeyWithSize = IncludeKeyInEncryptionString(privateKey, keySize);
                // set key 
                KeyPublish = publicKeyWithSize; // false to get the public key   
                KeyPrivate = privateKeyWithSize; // true to get the private key   

            }

            private string IncludeKeyInEncryptionString(string publicKey, int keySize)
            {
                return Convert.ToBase64String(Encoding.UTF8.GetBytes(keySize.ToString() + "!" + publicKey));
            }
        }
    }
}
