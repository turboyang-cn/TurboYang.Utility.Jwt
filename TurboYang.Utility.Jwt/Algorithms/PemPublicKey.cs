using System;
using System.Collections.Generic;
using System.Text;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public class PemPublicKey : IPemPublicKey
    {
        public PemPublicKey(String publicKey)
        {
            PublicKey = publicKey;
        }

        public String PublicKey { get; }

        public static implicit operator PemPublicKey(String publicKey)
        {
            return new PemPublicKey(publicKey);
        }

        public static implicit operator String(PemPublicKey publicKey)
        {
            return publicKey.PublicKey;
        }
    }
}
