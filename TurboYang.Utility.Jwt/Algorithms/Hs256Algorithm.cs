using System;
using System.Linq;
using System.Security.Cryptography;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public sealed class Hs256Algorithm : SymmetricAlgorithm
    {
        internal Hs256Algorithm()
        {
        }

        public Hs256Algorithm(String key)
            : base(key)
        {
        }

        public Hs256Algorithm(Byte[] key)
            : base(key)
        {
        }

        public override String Name => "HS256";

        public override Byte[] Sign(Byte[] data)
        {
            using (HMACSHA256 hmacSha256 = new HMACSHA256(Key))
            {
                return hmacSha256.ComputeHash(data);
            }
        }

        public override Boolean VerifySignature(Byte[] data, Byte[] signature)
        {
            using (HMACSHA256 hmacSha256 = new HMACSHA256(Key))
            {
                return Enumerable.SequenceEqual(hmacSha256.ComputeHash(data), signature);
            }
        }
    }
}
