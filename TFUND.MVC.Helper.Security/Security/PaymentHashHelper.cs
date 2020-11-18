using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;

namespace TFUND.MVC.Helper.Security
{
    /// <summary>
    /// Payment Hash Signature : HMAC-SHA256
    /// such as : LinePay ,and other
    /// </summary>
    public static class PaymentHashHelper
    {
        /// <summary>
        /// Simple HAMC-SHA256
        /// Signature = Base64(HMAC-SHA256(Your ChannelSecret, (Your ChannelSecret + URL Path + RequestBody + nonce)))
        /// </summary>
        /// <param name="keyHex"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static string LinePaySignature(string keyHex, string message)
        {
            keyHex = keyHex ?? "";
            var encoding = new System.Text.UTF8Encoding();
            byte[] keyByte = encoding.GetBytes(keyHex);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

        #region Hash Hex Functions
        /// <summary>
        /// HMAC hash method
        /// Example : expectedHex = "b436e3e86cb3800b3864aeecc8d06c126f005e7645803461717a8e4b2de3a905";
        //  string key = "57617b5d2349434b34734345635073433835777e2d244c31715535255a366773755a4d70532a5879793238235f707c4f7865753f3f446e633a21575643303f66";
        //  string message ="amount=100&currency=EUR";
        //  var hashHMACSHA = PaymentHashHelper.HashHMACSHAHex(key, message);
        //  Console.WriteLine("Result Hmac : " + hashHMACSHA);   // result of "hashHMACSHA" Must be equal to "expectedHex"
        /// </summary>
        /// <param name="keyHex"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static string HashHMACSHAHex(string keyHex, string message)
        {
            byte[] hash = HashHMAC(HexDecode(keyHex), StringEncode(message));
            return HashEncode(hash);
        }

        /// <summary>
        /// SHA hash method
        /// Example :
        //  string innerKey  = "61574d6b157f757d02457573556645750e0341481b127a07476303136c005145436c7b46651c6e4f4f040e1569464a794e534309097258550c17616075060950";
        //  string outerKey  = "0b3d27017f151f17682f1f193f0c2f1f64692b227178106d2d096979066a3b2f2906112c0f760425256e647f032c2013243929636318323f667d0b0a1f6c633a";
        //  string message ="amount=100&currency=EUR";
        //  var hashSHA = PaymentHashHelper.HashSHAHex(innerKey, outerKey, message);
        //  Console.WriteLine("Result Sha : " + hashSHA);
        /// </summary>
        /// <param name="innerKeyHex"></param>
        /// <param name="outerKeyHex"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static string HashSHAHex(string innerKeyHex, string outerKeyHex, string message)
        {
            byte[] hash = HashSHA(HexDecode(innerKeyHex), HexDecode(outerKeyHex), StringEncode(message));
            return HashEncode(hash);
        }
        #endregion

        #region Hash Functions
        private static byte[] HashHMAC(byte[] key, byte[] message)
        {
            var hash = new HMACSHA256(key);
            return hash.ComputeHash(message);
        }

        private static byte[] HashSHA(byte[] innerKey, byte[] outerKey, byte[] message)
        {
            var hash = new SHA256Managed();

            // Compute the hash for the inner data first
            byte[] innerData = new byte[innerKey.Length + message.Length];
            Buffer.BlockCopy(innerKey, 0, innerData, 0, innerKey.Length);
            Buffer.BlockCopy(message, 0, innerData, innerKey.Length, message.Length);
            byte[] innerHash = hash.ComputeHash(innerData);

            // Compute the entire hash
            byte[] data = new byte[outerKey.Length + innerHash.Length];
            Buffer.BlockCopy(outerKey, 0, data, 0, outerKey.Length);
            Buffer.BlockCopy(innerHash, 0, data, outerKey.Length, innerHash.Length);
            byte[] result = hash.ComputeHash(data);

            return result;
        }
        #endregion

        #region Encoding Helpers
        private static byte[] StringEncode(string text)
        {
            var encoding = new System.Text.UTF8Encoding();
            //var encoding = new ASCIIEncoding();
            return encoding.GetBytes(text);
        }

        private static string HashEncode(byte[] hash)
        {
            //return Convert.ToBase64String(hash);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private static byte[] HexDecode(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber);
            }
            return bytes;
        }
        #endregion
    }
}
