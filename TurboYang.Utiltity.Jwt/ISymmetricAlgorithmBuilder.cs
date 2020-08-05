using System;

namespace TurboYang.Utiltity.Jwt
{
    public interface ISymmetricAlgorithmBuilder
    {
        IAlgorithmWithKeyBuilder WithKey(Byte[] key);
        IAlgorithmWithKeyBuilder WithKey(String key);
    }
}
