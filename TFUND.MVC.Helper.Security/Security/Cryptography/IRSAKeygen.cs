using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TFUND.MVC.Helper.Security.RSACryptography
{
    public interface IRSAKeygen
    {
        ValueTuple<string, string> GenerateKeyPair(RSAKeySize keySize);

        bool SaveToFile(ValueTuple<string, string> key, string filepath = "");
    }
}
