using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TFUND.MVC.Helper.Security.RSACryptography
{
    /// <summary>
    /// Represents an RSA key's size.
    /// Possible values are 512-bit, 1024-bit, 2048-bit and 4096-bit.
    /// The bigger, the slower, the safer.
    /// </summary>
    public enum RSAKeySize : int
    {
        /// <summary>
        /// 512-bit RSA Key (don't use this please!).
        /// </summary>
        [Obsolete]
        RSA512 = 512,

        /// <summary>
        /// 1024-bit RSA Key.
        /// </summary>
        RSA1024 = 1024,

        /// <summary>
        /// 2048-bit RSA Key.
        /// </summary>
        RSA2048 = 2048,

        /// <summary>
        /// 4096-bit RSA Key.
        /// </summary>
        RSA4096 = 4096
    }
}
