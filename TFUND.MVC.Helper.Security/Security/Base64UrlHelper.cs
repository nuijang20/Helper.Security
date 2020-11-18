using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TFUND.MVC.Helper.Security
{

    // -------------------------------------------
    // Usage
    // -------------------------------------------
    /*
    // Encode
    var bytes1 = new byte[] { 72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33 };
    var encodedString1 = Base64Url.Encode(bytes1);
    WriteLine(encodedString1); // SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ
 
    // Decode
    var encodedString2 = "SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ";
    var bytes2 = Base64Url.Decode(encodedString2);
    WriteLine(System.Text.Encoding.UTF8.GetString(bytes2)); // Hello Base64Url encoding!

    */
    public class Base64UrlHelper
    {
        public static string Encode(byte[] input)
        {
            var output = Convert.ToBase64String(input);

            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding

            return output;
        }

        public static byte[] Decode(string input)
        {
            var output = input;

            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding

            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    output += "==";
                    break; // Two pad chars
                case 3:
                    output += "=";
                    break; // One pad char
                default:
                    throw new ArgumentOutOfRangeException("Illegal base64url string!");
            }

            var converted = Convert.FromBase64String(output); // Standard base64 decoder

            return converted;
        }

        public static string Base64Encode(string txtValue)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(txtValue);
            return System.Convert.ToBase64String(plainTextBytes);
        }
        public static string Base64Decode(string txtValue)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(txtValue);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

    }
}
