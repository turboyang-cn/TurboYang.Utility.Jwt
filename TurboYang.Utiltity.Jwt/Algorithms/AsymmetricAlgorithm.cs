using System;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public abstract class AsymmetricAlgorithm : Algorithm
    {
        internal AsymmetricAlgorithm()
        {
        }

        public AsymmetricAlgorithm(IPemPublicKey publicKey)
        {
            PublicKey = publicKey;
        }

        public AsymmetricAlgorithm(IPemPrivateKey privateKey)
        {
            PrivateKey = privateKey;
        }

        public AsymmetricAlgorithm(String publicKey, String privateKey)
            : this(new PemKeyPair(publicKey, privateKey))
        {
        }

        public AsymmetricAlgorithm(PemKeyPair keyPair)
        {
            PublicKey = keyPair;
            PrivateKey = keyPair;
        }

        internal protected IPemPublicKey PublicKey { get; internal set; }
        internal protected IPemPrivateKey PrivateKey { get; internal set; }
    }
}
