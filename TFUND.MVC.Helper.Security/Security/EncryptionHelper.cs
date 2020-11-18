using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
namespace TFUND.MVC.Helper.Security
{
    public class EncryptionHelper
    {

        #region AES 
        private static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
        #endregion

        /// <summary>
        /// Encrypt String Method 
        /// Example : 
        /// var strencrypt = EncryptionHelper.AES_EncryptText("PrivateKey", "123456789")
        /// Result :
        /// cGBffELTG_R97rS_BYhNww
        /// </summary>
        /// <param name="strEncode"></param>
        /// <param name="txtValue"></param>
        /// <returns></returns>
        
        public static string AES_EncryptText(string strEncode, string txtValue)
        {
            try
            {
                // Get the bytes of the string
                byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(txtValue);
                byte[] EncodeBytes = Encoding.UTF8.GetBytes(strEncode);

                // Hash the password with SHA256
                EncodeBytes = SHA256.Create().ComputeHash(EncodeBytes);

                byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, EncodeBytes);

                //string result = Convert.ToBase64String(bytesEncrypted);
                // Base64UrL Encrypt for web
                string result = Base64UrlHelper.Encode(bytesEncrypted);
                return result;
            }
            catch (Exception ex) {
                return "Error :" + ex.Message;
            }
        }

        /// <summary>
        /// Decrypt String Method 
        /// Example : 
        /// var strdecrypt = EncryptionHelper.AES_DecryptText("PrivateKey", "cGBffELTG_R97rS_BYhNww")
        /// Result :
        /// 123456789        
        /// </summary>
        /// <param name="strEncode"></param>
        /// <param name="txtValue"></param>
        /// <returns></returns>
        public static string AES_DecryptText(string strEncode, string txtValue)
        {
            try
            {
                // Get the bytes of the string                
                // Base64UrL Decrypt for web
                byte[] bytesToBeDecrypted = Base64UrlHelper.Decode(txtValue);
                //byte[] bytesToBeDecrypted = Convert.FromBase64String(txtValue);

                byte[] EncodeBytes = Encoding.UTF8.GetBytes(strEncode);
                EncodeBytes = SHA256.Create().ComputeHash(EncodeBytes);

                byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, EncodeBytes);

                string result = Encoding.UTF8.GetString(bytesDecrypted);

                return result;
            }
            catch (Exception ex) {
                return "Error :" + ex.Message;
            }
        }



    }


}
