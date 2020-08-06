using System;
using System.Collections.Generic;
using System.Text;
using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public interface IAsymmetricAlgorithmBuilder
    {
        IAlgorithmWithKeyBuilder WithKey(IPemPrivateKey privateKey);
        IAlgorithmWithKeyBuilder WithKey(IPemPublicKey publicKey);
        IAlgorithmWithKeyBuilder WithPrivateKey(String privateKey);
        IAlgorithmWithKeyBuilder WithPublicKey(String publicKey);
        IAlgorithmWithKeyBuilder WithKeys(PemKeyPair keyPair);
    }
}
