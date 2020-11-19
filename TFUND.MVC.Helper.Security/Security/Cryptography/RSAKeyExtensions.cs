using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;

namespace TFUND.MVC.Helper.Security.RSACryptography
{
    public static class RSAKeyExtensions
    {
        /// <summary>
        /// Converts a BouncyCastle <see cref="AsymmetricKeyParameter"/> to a PEM-formatted <c>string</c>.
        /// </summary>
        /// <param name="key">The key to stringify.</param>
        /// <returns><c>string</c> containing the PEM-formatted key.</returns>
        public static string ToPemString(this AsymmetricKeyParameter key)
        {
            using (var sw = new StringWriter())
            {
                var pem = new PemWriter(sw);
                pem.WriteObject(key);
                pem.Writer.Flush();
                return sw.ToString();
            }
        }
    }
}
