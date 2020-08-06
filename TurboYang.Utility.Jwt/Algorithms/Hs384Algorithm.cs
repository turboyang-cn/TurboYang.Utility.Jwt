using System;
using System.Linq;
using System.Security.Cryptography;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public sealed class Hs384Algorithm : SymmetricAlgorithm
    {
        internal Hs384Algorithm()
        {
        }

        public Hs384Algorithm(String key)
            : base(key)
        {
        }

        public Hs384Algorithm(Byte[] key)
            : base(key)
        {
        }

        public override String Name => "HS384";

        public override Byte[] Sign(Byte[] data)
        {
            using (HMACSHA384 hmacSha384 = new HMACSHA384(Key))
            {
                return hmacSha384.ComputeHash(data);
            }
        }

        public override Boolean VerifySignature(Byte[] data, Byte[] signature)
        {
            using (HMACSHA384 hmacSha384 = new HMACSHA384(Key))
            {
                return Enumerable.SequenceEqual(hmacSha384.ComputeHash(data), signature);
            }
        }
    }
}
