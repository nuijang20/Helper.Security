using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using System.IO;

namespace TFUND.MVC.Helper.Security.RSACryptography
{
    /// <summary>
    /// Asymmetric Cryptography RSA Library
    /// </summary>
    public class RSAKeygen : IRSAKeygen
    {
        private readonly Action<string> errorCallback;
        private readonly string publickey = "public_rsa.key";
        private readonly string privatekey = "private_rsa.key";
        /// <summary>
        /// Creates a new asymmetric RSA key generator.
        /// </summary>
        /// <param name="errorCallback"></param>
        public RSAKeygen(Action<string> errorCallback = null)
        {
            this.errorCallback = errorCallback;
        }

        /// <summary>
        /// Generates a new RSA key pair <see cref="Tuple"/> using the provided RSA key size parameter <paramref name="keySize"/>.<para> </para>
        /// Returns the RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key.<para> </para>
        /// If generation failed for some reason, <c>null</c> is returned.
        /// </summary>
        /// <param name="keySize">The desired RSA key size. Can be 512-bit, 1024-bit, 2048-bit or 4096-bit.</param>
        /// <returns>The key pair <see cref="Tuple"/>, where the first item is the public RSA key and the second one is the private key (both PEM-formatted). If key generation failed, both tuple items are <c>null</c>.</returns>
        public ValueTuple<string, string> GenerateKeyPair(RSAKeySize keySize)
        {
            try
            {
                var keygen = new RsaKeyPairGenerator();
                keygen.Init(new KeyGenerationParameters(new SecureRandom(), (int)keySize));
                AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();
                return (keyPair.Public.ToPemString(), keyPair.Private.ToPemString());
            }
            catch (Exception e)
            {
                errorCallback?.Invoke($"{nameof(RSAKeygen)}::{nameof(GenerateKeyPair)}: RSA key pair generation failed. Thrown exception: {e.ToString()}");
                return (null, null);
            }
        }

        public bool SaveToFile(ValueTuple<string, string> key , string filepath="")
        {   
            var setfilePath = (filepath == null || filepath == "") ? AppDomain.CurrentDomain.BaseDirectory + "Keys\\" : filepath;
            var folder = "KeyPair";
            var version = (Directory.GetDirectories(string.Format("{0}", setfilePath)).Length == 0) ? 1 : Directory.GetDirectories(string.Format("{0}", setfilePath)).Length + 1;
            setfilePath = string.Format("{0}{1}{2}", setfilePath, folder, version);
            // check folder key
            if (Directory.Exists(setfilePath) == false)
            {
                // create folder
                Directory.CreateDirectory(setfilePath);
                // create public file 
                var keyfiles = new Dictionary<string, string>() {
                    { publickey , key.Item1 },
                    { privatekey , key.Item2 }
                };

                foreach (var f in keyfiles)
                {
                    using (StreamWriter sw = File.CreateText(string.Format("{0}\\{1}", setfilePath,f.Key)))
                    {
                        sw.WriteLine(f.Value);
                    }
                }
            }

            return true;
        }
    }
}
