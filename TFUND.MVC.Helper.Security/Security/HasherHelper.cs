using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace TFUND.MVC.Helper.Security
{
    public class HasherHelper
    {
        #region property
        private const int SaltSize = 16;
        private const int HashSize = 20;
        private const string keyHashSupport = "$TFHASH$V1$";
        private const int iterations = 10000;

        /// <summary>
        /// Hash Key Support คือ KeyHash ที่จ
        /// </summary>
        /// <param name="hashString"></param>
        /// <returns></returns>       
        public static bool IsHashSupported(string hashString)
        {
            return hashString.Contains(keyHashSupport);
        }

        public static string Message { get; set; }
        #endregion

        /// <summary>
        /// Creates a hash from a password
        /// Example : var result = HasherHelper.Hash("123456");
        /// Result :  Qs4gIHiM$TFHASH$V1$dCnbEg1Xb44bZ2GuZuk2/nDm6QUqfUiCmnj6RnDa
        /// </summary>
        /// <param name="password">the password</param>
        /// <returns>the hash</returns>
        public static string Hash(string password)
        {
            //create salt
            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[SaltSize]);
            //create hash
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            var hash = pbkdf2.GetBytes(HashSize);
            //combine salt and hash
            var hashBytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);
            //convert to base64
            var base64Hash = Convert.ToBase64String(hashBytes);
            //format hash with extra information

            // กำหนด Key support random ไว้ภายในชุด hashstring
            int MaxLength = ((base64Hash.Length) - keyHashSupport.Length)-1;

            Random random = new Random();
            int hashMidLength = random.Next(1, MaxLength); 
            
            var hashLeft = base64Hash.Substring(0, hashMidLength);
            var hashRight = base64Hash.Substring(hashLeft.Length, (base64Hash.Length - hashLeft.Length));
            return string.Format("{0}{1}{2}", hashLeft , keyHashSupport, hashRight);
        }


        /// <summary>
        /// verify a password with hash
        /*
            if (HasherHelper.Verify("123456", "Qs4gIHiM$TFHASH$V2$dCnbEg1Xb44bZ2GuZuk2/nDm6QUqfUiCmnj6RnDa"))
            {
                result = "Success";
            }
            else
            {
                result = HasherHelper.Message;
            }
        */
        /// </summary>
        /// <param name="password">the password</param>
        /// <param name="hashedPassword">the hash</param>
        /// <returns>could be verified?</returns>
        public static bool Verify(string password, string hashedPassword)
        {
            try
            {
                //check hash
                if (!IsHashSupported(hashedPassword))
                {
                    //throw new NotSupportedException("The hashtype is not supported");
                    Message = "The HashSupport not found";
                    return false;
                }
                //extract iteration and Base64 string   xx$TFHASH$V1$xx
                var splittedHashString = hashedPassword.Replace(keyHashSupport, "$").Split('$');

                var base64Hash = splittedHashString[0] + splittedHashString[1];
                //get hashbytes
                var hashBytes = Convert.FromBase64String(base64Hash);
                //get salt
                var salt = new byte[SaltSize];
                Array.Copy(hashBytes, 0, salt, 0, SaltSize);
                //create hash with given salt
                var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
                byte[] hash = pbkdf2.GetBytes(HashSize);
                //get result
                for (var i = 0; i < HashSize; i++)
                {
                    if (hashBytes[i + SaltSize] != hash[i])
                    {
                        Message = "Verify Failure";
                        return false;
                    }
                }
            }
            catch(Exception ex)
            {
                Message = "Error :"+ex.Message;
                return false;
            }

            return true;
        }

    }
}
