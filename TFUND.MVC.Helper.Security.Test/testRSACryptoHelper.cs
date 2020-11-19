using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TFUND.MVC.Helper.Security.RSACryptography;
using System.Threading.Tasks;
using System.IO;

namespace TFUND.MVC.Helper.Security.Test
{
    /// <summary>
    /// Summary description for testRSACryptoHelper
    /// </summary>
    [TestClass]
    public class testRSACryptoHelper
    {
        private readonly RSACryptography.IRSAKeygen keygen = new RSACryptography.RSAKeygen();
        private readonly RSACryptography.IRSACryptoHelper rsa = new RSACryptography.RSACryptoHelper();
        private string keypath;

        private readonly string publickey = File.ReadAllText("keys/KeyPair1/public_rsa.key");
        private readonly string privateKey = File.ReadAllText("keys/KeyPair1/private_rsa.key");
        
        public testRSACryptoHelper()
        {
            //
            // TODO: Add constructor logic here
            //
            keypath = AppDomain.CurrentDomain.BaseDirectory + "\\Keys\\";
        }


        [TestMethod]
        public void Test_GenerateKeyPair()
        {
            var keySize =RSACryptography.RSAKeySize.RSA2048;
            var key = keygen.GenerateKeyPair(keySize);
            keygen.SaveToFile(key, keypath);
        }

        [TestMethod]
        public void Test_RSACrypto()
        {
            var strtext = "579/50   ซอยพระรามที่ 2 ซอย 25  แขวงบางมด เขตจอมทอง กรุงเทพมหานคร 579/50   ซอยพระรามที่ 2 ซอย 25  แขวงบางมด เขตจอมทอง กรุงเทพมหานคร579/50   ซอยพระรามที่ 2 ซอย 25  แขวงบางมด เขตจอมทอง กรุงเทพมหานคร579/50   ซอยพระรามที่ 2 ซอย 25  แขวงบางมด เขตจอมทอง กรุงเทพมหานคร579/50   ซอยพระรามที่ 2 ซอย 25  แขวงบางมด เขตจอมทอง กรุงเทพมหานคร";
            string strEncrypt = rsa.EncryptData(strtext, publickey );
            string strDecrypt = rsa.DecryptData(strEncrypt, privateKey);

            // descript equal string before encrypt
            Assert.AreEqual(strDecrypt, strtext);
        }
    }
}
