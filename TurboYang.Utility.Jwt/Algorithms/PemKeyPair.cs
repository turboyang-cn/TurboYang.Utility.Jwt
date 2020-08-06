using System;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public sealed class PemKeyPair : IPemPrivateKey, IPemPublicKey
    {
        public PemKeyPair(String publicKey, String privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        public String PublicKey { get; }
        public String PrivateKey { get; }
    }
}
