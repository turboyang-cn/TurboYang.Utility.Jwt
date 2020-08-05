using System;
using System.Collections.Generic;
using System.Text;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public class PemPrivateKey : IPemPrivateKey
    {
        public PemPrivateKey(String privateKey)
        {
            PrivateKey = privateKey;
        }

        public String PrivateKey { get; }

        public static implicit operator PemPrivateKey(String privateKey)
        {
            return new PemPrivateKey(privateKey);
        }

        public static implicit operator String(PemPrivateKey privateKey)
        {
            return privateKey.PrivateKey;
        }
    }
}
