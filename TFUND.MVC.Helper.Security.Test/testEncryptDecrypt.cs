using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TFUND.MVC.Helper.Security.Test
{
    [TestClass]
    public class testEncryptDecrypt
    {
        [TestMethod]
        public void Encrypt_String()
        {
            var SecretKey = "MjA0OCE8UlNBS2V5VmFsdWU+PE1vZHVsdXM+cm52ZGJXalAxMWRhbGgraWtHdXZ0dXM5Y2RpcVhuYk1BaUtPQVg1ejVBUTFkUXFrU0ZleHFrWW9USHVBelFITHJxT20rejBicjJpRW8wVVVlRU9XRzg0MGxHVW5YTjJQK2swZEEzNS9udUtQcU1xVUtNdkJWZFJkcmJRMC9Jdnpkd09MeFJFRGFDUmZ4YkZ4RGRuTUVDN0NmK1FqOENnYUtkL1RDV2RXZzJOSVBpaWV0VWJQVXY5c2pJZEtmMEFaY083U1YxMHplN3hzdHh1dXhrSTYvOEJ2RVM4MWIvaStMNmF4SktzeW4wRG9LUUNxa3ZaWE4xU2VKUEdLY0Z1elBFS0JzVmVlUEliOTBVb0R4b2pJNTc1UGg5U0RmZ3krR28weURtdVFjTHB5UzNvaEJ1QzVKVGt0d3hJM2gzSVVkTE5DS2w4OFVEZDdOcG1xbmFYU1pRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPnp3OTBrdWZOUEdQak1lUVUrMXV2UU5lRU5PclB3QkVidzJURm5ucEVINHpZb3dtNW9RZE1aMzBOQ0YxcThURUlybUk1c1NDby8wWFRKNENGbjI0Z1FJVE50ZUN1RDR5TUVTeUJldURLOTUxbTU4L3FSRUF6aTIwRzhDUzBORXNOSnBJbGFrVFNDSVUzVVZ1bU9SZjE5ZDB1STZSTjFSa2JXQS9nc200TUdrTT08L1A+PFE+MTdsUGtLMTNjZmNLSml3R3IxSmJzeHYvcVlHbXFTZlpjbFVQQnlhdkZBVWdxOTVERHp4Mm5oUHFaQkwrWUQzZm9NRGNRMHdJS0w3N0VRbytrNElHbjVBOTM3VGo5eFMycG90ODVxbnQvVXRwNS84S1h1UUE0UklEQUdHd0tjVUJISkR4d1dPazk2VHo1V3BYVzc2Uzk5TEIrbTFxZjJFOWVpZ0VYbVZ6T2pjPTwvUT48RFA+RjNJN2xBcjFmWG9lRnQ4cDFSQ2J0cTd3eElFMlJ4eG8xV1pLemxndjhKYWxUVWpqb1MxUFpJU1BmanY5eVJQeFZMWEFyS0x6SC96TEhUVDdiSU11MmI5di84RlNWR1pvMGVVRlFHSEYrZVh6Nmhuc0FCQjVCYmV4eW0yTmprSlZXZUhBcE5qb0k1amFHN2RTQ2pNQllmYktxN1NHTDdRcEdYNnF4ZW1hS3pzPTwvRFA+PERRPm5HZkRCRWFBdjZRNU80dllITzA5aHhMWnZuQStBWTdlM1VKR2J3emhDMGJjZFQva3B2dFRsVEVqVkFOaFl5MzVJWGd6T3FlNWtyRkZId21xYlJCczlPdURzTnBhSGg1cWZ6M0xCUUpYaHJwU3d0M3JDdm1NbWFLUmdvbFJURGVGb3N5RU80NmZZTjI3NTYyK1FNcGZqRWJHVldkWE81dXBFeFJJZHBoZmZ1az08L0RRPjxJbnZlcnNlUT5taHdxUXIwaytqeWxXMzEyYkdlVjJrVmxUMEJ6UVFOemtTamdzR0FENEFqUUVNR2NIVFNkQ3JLS01FM1hBekZhNFhSWlA3cm5waEpFd09kdmw1cW5ValF3RCs3aSswU3ozTTliTENXSCtieFdFT1pZa0pIeXRJMi8wZ1pjUlJQMFRhZFd1S0lJN0FhN1Jjb1NtL2g3TWcvUEIxV1FCTHJUdFRyc013OEQ0aEE9PC9JbnZlcnNlUT48RD5aaUdZdmNjQkNZSlhRdEpubkhOOEdlemVQWHBlVndiZ2FVdUNwYnMzNkxyUjg1MTBCZWhXMVYxVmoxY25VRmlCdWNxUEhqWnBzeVhScGFQMDFHUnpRL2xTYTU0K0NTeWpieGFlS2dKc2Z6c01iZmVOKzhjd2RxWGs0NTA4K3FxTXF4aEhRdVd2Z2REd3drNFg1OHlabHN0WUMvWWxWeGlTSC9xa2s3ZUtPMEwxZURxRm0zbkRoSkZJcm45c3Y4K0ZEMEdBWHZvU1lENHRvTmxvc0E3dlFVR3lRSXNTeW9yemN1Y1NweFI4MUlpM29XLytpSzRzYnoyZDBUNURIb2ROSllJUGVENFRmTTNjM2tlWVFieG4wYXVBL0YwRy9IQVRiSnpLeWUyMGZrT3JJcyt4NGo2dUNUM21XY012YTdBOWdpVGJSeGJEVXp1TzNmQW1xTjRaRFE9PTwvRD48L1JTQUtleVZhbHVlPg==";
            var StringKey = "สวัสดิรักษาสิทธิ์                                      asdfasdfasdf2tยนบนบงยนงวสฝ่สาเีดำไถพ--ภฟำดฟหกดฟหกดฟหดฟหกด                                 ";
            var result = string.Empty;
            try
            {
                // encrypt
                result = EncryptionHelper.AES_EncryptText(SecretKey, StringKey);

                // decrypt
                var result2 = EncryptionHelper.AES_DecryptText(SecretKey, result);
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

        #region RSA Helper
        private string PublicKey { get; set; }
        private string PrivateKey { get; set; }
        private void RSACryptoGenerate()
        {
            var key = new RSACryptoHelper.RSACryptoGenerator();
            PublicKey = key.KeyPublish;
            PrivateKey = key.KeyPrivate;
        }
        [TestMethod]
        public void RSACrypto_Test()
        {
            // generate key
            RSACryptoGenerate();
            // ==================

            var rsa = new RSACryptoHelper.RSACryptoGenerator(this.PublicKey,this.PrivateKey);
            RSACryptoHelper.RSACryptoUtil.SetContainer(rsa);

            var strValue = "245 ม.ลาซาลเพลซ ซ.ลาซาล24 ถ.สุขุมวิท 105 แขวงบางนา เขตบางนา กรุงเทพ 10260";
            var encryptValue = RSACryptoHelper.RSACryptoUtil.EncryptData(strValue);

            var result = RSACryptoHelper.RSACryptoUtil.DecryptData(encryptValue);

            Assert.IsNotNull(result);
        }
        #endregion  
    }
}
