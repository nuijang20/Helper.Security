using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TFUND.MVC.Helper.Security.Test
{
    [TestClass]
    public class EncryptDecrypt
    {
        [TestMethod]
        public void Encrypt_String()
        {
            var SecretKey = "50D9CC22 - 7019 - 4CFA - 9917 - EAD6DB42165B";
            var StringKey = "123456789";
            var result = string.Empty;
            try
            {
                result = EncryptionHelper.AES_EncryptText(SecretKey, StringKey);
            }catch(Exception ex)
            {
                result = null;
            }
            
            Assert.IsNotNull(result);            
        }
        #region test hasherHelper
        [TestMethod]
        public void Hash_password()
        {
            var Password = "123456";
            var result = string.Empty;
            try
            {
                result = HasherHelper.Hash(Password);
            }
            catch (Exception ex)
            {
                result = null;
            }

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public void Hash_Verify()
        {
            var Password = "123456";
            var HashKey = "Qs4gIHiM$TFHASH$V2$dCnbEg1Xb44bZ2GuZuk2/nDm6QUqfUiCmnj6RnDa";
            var result = string.Empty;
            try
            {
                if (HasherHelper.Verify(Password, HashKey))
                {
                    result = "TRUE";
                }
                else
                {
                    result = HasherHelper.Message;
                }
            }
            catch (Exception ex)
            {
                result = null;
            }

            Assert.Equals(result, "TRUE");
        }
        #endregion
    }
}
