using System;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;

namespace TFUND.MVC.Helper.Security.RSACryptography
{
    /// <summary>
    /// Interface RSACryptoHelper for Encryption and Decryption
    /// </summary>
    public interface IRSACryptoHelper
    {
        #region Encrypt and Decrypt
        string EncryptData(string text, string publicKey);
        string DecryptData(string encryptedText, string privateKey);

        #endregion
    }
}
