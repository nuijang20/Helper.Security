using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;

namespace TFUND.MVC.Helper.Security.RSACryptography
{
    public class RSACryptoHelper : IRSACryptoHelper
    {
        /// <summary>
        /// The algorithm used for encrypting/decrypting string
        /// </summary>

        public string EncryptData(string text, string publicKey)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(publicKey))
            {
                return string.Empty;
            }
            try
            {
                return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(text), publicKey));
            }
            catch
            {
                return null;
            }
        }

        public string DecryptData(string encryptedText, string privateKey)
        {
            if (string.IsNullOrEmpty(encryptedText) || string.IsNullOrEmpty(privateKey))
            {
                return string.Empty;
            }
            try
            {
                return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(encryptedText), privateKey));
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Encrypts the specified bytes using the provided RSA public key
        /// </summary>
        /// <returns>The encrypted bytes</returns>
        private byte[] Encrypt(byte[] data, string publicKey)
        {
            if (data is null || data.Length == 0 || string.IsNullOrEmpty(publicKey))
            {
                throw new ArgumentException("Data or Key is null or empty", "data");
            }

            try
            {
                AsymmetricCipherKeyPair keyPair = StringToKeyPair(publicKey);
                ICipherParameters key = keyPair?.Public ?? StringToKeyParameters(publicKey);

                return ProcessData(data, key, true);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Decrypts the specified bytes using the provided private RSA key
        /// </summary>
        /// <returns>Decrypted bytes</returns>
        private byte[] Decrypt(byte[] encryptedData, string privateKey)
        {
            if (encryptedData is null || encryptedData.Length == 0 || string.IsNullOrEmpty(privateKey))
            {
                throw new ArgumentException("encryptedData or PrivateKey is null or empty", "data");
            }

            try
            {
                return ProcessData(encryptedData, StringToKeyPair(privateKey).Private, false);
            }
            catch
            {
                return null;
            }
        }



        #region Conversions

        /// <summary>
        /// Tries to convert a PEM-formatted <c>string</c> => <see cref="AsymmetricCipherKeyPair"/>.<para> </para>
        /// Only possible if the provided key is the private key (public keys are typically read with the <see cref="PemReader"/> as <see cref="RsaKeyParameters"/>).
        /// </summary>
        /// <param name="rsaKeyPem">The PEM-formatted key <c>string</c> to convert.</param>
        /// <returns>The converted <see cref="AsymmetricCipherKeyPair"/>; <c>null</c> if the provided key <c>string</c> was <c>null</c>, empty or the public key.</returns>
        private static AsymmetricCipherKeyPair StringToKeyPair(string rsaKey)
        {
            if (string.IsNullOrEmpty(rsaKey))
            {
                return null;
            }

            var stringReader = new StringReader(rsaKey);
            try
            {
                var Reader = new PemReader(stringReader);
                return Reader.ReadObject() as AsymmetricCipherKeyPair;
            }
            catch
            {
                return null;
            }
            finally
            {
                stringReader.Dispose();
            }
        }

        /// <summary>
        /// Tries to convert a PEM-formatted <c>string</c> => <see cref="RsaKeyParameters"/>.<para> </para>
        /// </summary>
        /// <param name="rsaKey">The PEM-formatted key <c>string</c> to convert.</param>
        /// <returns>The converted <see cref="RsaKeyParameters"/>; <c>null</c> if the provided key <c>string</c> was <c>null</c> or empty.</returns>
        private static RsaKeyParameters StringToKeyParameters(string rsaKey)
        {
            if (string.IsNullOrEmpty(rsaKey))
            {
                return null;
            }

            var stringReader = new StringReader(rsaKey);
            try
            {
                var pemReader = new PemReader(stringReader);
                return pemReader.ReadObject() as RsaKeyParameters;
            }
            catch
            {
                return null;
            }
            finally
            {
                stringReader.Dispose();
            }
        }

        /// <summary>
        /// Process Encrypts or decrypts
        /// </summary>
        /// <param name="data">The data to encrypt or decrypt</param>
        /// <param name="key">The RSA key to use for encryption/decryption.</param>
        /// <param name="encrypt">Should the method encrypt the passed input <paramref name="data"/> or attempt to decrypt it?</param>
        /// <returns>The processed data <c>byte[]</c> array; exceptions are thrown in case of a failure.</returns>
        private static byte[] ProcessData(byte[] data, ICipherParameters key, bool encrypt)
        {
            // PKCS1 OAEP paddings
            OaepEncoding eng = new OaepEncoding(new RsaEngine());
            eng.Init(encrypt, key);

            int length = data.Length;
            int blockSize = eng.GetInputBlockSize();

            List<byte> processedBytes = new List<byte>(length);

            for (int chunkPosition = 0; chunkPosition < length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, length - chunkPosition);
                processedBytes.AddRange(eng.ProcessBlock(data, chunkPosition, chunkSize));
            }

            return processedBytes.ToArray();
        }

        #endregion
    }
}
