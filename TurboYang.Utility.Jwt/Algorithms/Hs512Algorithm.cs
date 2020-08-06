using System;
using System.Linq;
using System.Security.Cryptography;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public sealed class Hs512Algorithm : SymmetricAlgorithm
    {
        internal Hs512Algorithm()
        {
        }

        public Hs512Algorithm(String key)
            : base(key)
        {
        }

        public Hs512Algorithm(Byte[] key)
            : base(key)
        {
        }

        public override String Name => "HS512";

        public override Byte[] Sign(Byte[] data)
        {
            using (HMACSHA512 hmacSha512 = new HMACSHA512(Key))
            {
                return hmacSha512.ComputeHash(data);
            }
        }

        public override Boolean VerifySignature(Byte[] data, Byte[] signature)
        {
            using (HMACSHA512 hmacSha512 = new HMACSHA512(Key))
            {
                return Enumerable.SequenceEqual(hmacSha512.ComputeHash(data), signature);
            }
        }
    }
}
