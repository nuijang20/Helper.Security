using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TFUND.MVC.Helper.Security.Test
{
    [TestClass]
    public class testHMAC_SHA
    {
        [TestMethod]
        public void HashHMACSHA2576()
        {
            var result = string.Empty;
            var result2 = string.Empty;
            try
            {
                // expectedHex = "b436e3e86cb3800b3864aeecc8d06c126f005e7645803461717a8e4b2de3a905";
                string key = "57617b5d2349434b34734345635073433835777e2d244c31715535255a366773755a4d70532a5879793238235f707c4f7865753f3f446e633a21575643303f66";
                string message = "amount=100&currency=EUR";
                result = PaymentHashHelper.LinePaySignature(key, message);
                result2 = PaymentHashHelper.HashHMACSHAHex(key, message);
            }
            catch (Exception ex)
            {
                result = null;
            }
            //Assert.Equals(result, result2);
            Assert.IsNotNull(result);
        }
    }
}
