using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace TFUND.MVC.Helper.Security
{
    /// <summary>
    /// Generate Key
    /// </summary>
    public class KeyGeneratorHelper
    {
        public static string GetUniqueKey(int maxSize = 20 , bool upperFlag=true , bool includeNumber=true)
        {
            string allowedChars = "abcdefghijklmnopqrstuvwxyz";
            string allowedCharsUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string allowedNumber = "1234567890";
            string keyChars = allowedChars + ((upperFlag) ? allowedCharsUpper : "") + ((includeNumber) ? allowedNumber : "");

            char[] chars = new char[62];
            chars = keyChars.ToCharArray();
            byte[] data = new byte[1];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[maxSize];
                crypto.GetNonZeroBytes(data);
            }
            StringBuilder result = new StringBuilder(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }

        #region OTP Generater
        /// <summary>
        /// Generate Unique Number
        /// </summary>
        /// <param name="maxSize"></param>
        /// <returns></returns>
        public static string GetUniqueNumber(int maxSize = 6)
        {
            string numbers = "1234567890";

            string characters = numbers;
            int length = maxSize;
            string otp = string.Empty;
            for (int i = 0; i < length; i++)
            {
                string character = string.Empty;
                do
                {
                    int index = new Random().Next(0, characters.Length);
                    character = characters.ToCharArray()[index].ToString();
                } while (otp.IndexOf(character) != -1);
                otp += character;
            }
            StringBuilder result = new StringBuilder(maxSize);
            result.Append(otp);
            return result.ToString();
        }


        private static string OTPCharacters(int maxSize)
        {
            Int32 OTPLength = maxSize;
            string NewCharacters = "";
            //This one tells you which characters are allowed in this new password
            string allowedChars = "";
            //Here Specify your OTP Characters
            allowedChars = "1,2,3,4,5,6,7,8,9,0";

            char[] sep = { ',' };
            string[] arr = allowedChars.Split(sep);

            string IDString = "";
            string temp = "";

            //utilize the "random" class
            Random rand = new Random();


            for (int i = 0; i < OTPLength; i++)
            {
                temp = arr[rand.Next(0, arr.Length)];
                IDString += temp;
                NewCharacters = IDString;
            }

            return NewCharacters;
        }

        public static string OTPGenerator(int maxSize = 6)
        {
            int length = maxSize;
            string oneTimePassword = "";

            #region Set uniqueIdentity
            string uniqueIdentity = OTPCharacters(maxSize);
            Random rng = new Random();
            string uniqueCustomerIdentity = rng.Next(10).ToString();

            DateTime dateTime = DateTime.Now;
            string _strParsedReqNo = dateTime.Day.ToString();
            _strParsedReqNo = _strParsedReqNo + dateTime.Month.ToString();
            _strParsedReqNo = _strParsedReqNo + dateTime.Year.ToString();
            _strParsedReqNo = _strParsedReqNo + dateTime.Hour.ToString();
            _strParsedReqNo = _strParsedReqNo + dateTime.Minute.ToString();
            _strParsedReqNo = _strParsedReqNo + dateTime.Second.ToString();
            _strParsedReqNo = _strParsedReqNo + dateTime.Millisecond.ToString();
            _strParsedReqNo = _strParsedReqNo + uniqueCustomerIdentity;


            _strParsedReqNo = uniqueIdentity + uniqueCustomerIdentity;
            #endregion


            using (MD5 md5 = MD5.Create())
            {
                //Get hash code of entered request id in byte format.
                byte[] _reqByte = md5.ComputeHash(Encoding.UTF8.GetBytes(_strParsedReqNo));
                //convert byte array to integer.
                int _parsedReqNo = BitConverter.ToInt32(_reqByte, 0);
                string _strParsedReqId = Math.Abs(_parsedReqNo).ToString();
                //Check if length of hash code is less than 9.
                //If so, then prepend multiple zeros upto the length becomes atleast 9 characters.
                if (_strParsedReqId.Length < 9)
                {
                    StringBuilder sb = new StringBuilder(_strParsedReqId);
                    for (int k = 0; k < (9 - _strParsedReqId.Length); k++)
                    {
                        sb.Insert(0, '0');
                    }
                    _strParsedReqId = sb.ToString();
                }
                oneTimePassword = _strParsedReqId;
            }

            if (oneTimePassword.Length >= length)
            {
                oneTimePassword = oneTimePassword.Substring(0, length);
            }
            return oneTimePassword;
        }
        #endregion

    }
}
