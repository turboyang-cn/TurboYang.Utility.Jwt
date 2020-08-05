using System;
using System.Collections.Generic;
using System.Text;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public sealed class NoneAlgorithm : Algorithm
    {
        public override String Name => "none";

        public override Byte[] Sign(Byte[] data)
        {
            return new Byte[0];
        }

        public override Boolean VerifySignature(Byte[] data, Byte[] signature)
        {
            return true;
        }
    }
}
