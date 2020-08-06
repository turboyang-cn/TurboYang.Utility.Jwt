using System;

namespace TurboYang.Utility.Jwt
{
    public interface ISymmetricAlgorithmBuilder
    {
        IAlgorithmWithKeyBuilder WithKey(Byte[] key);
        IAlgorithmWithKeyBuilder WithKey(String key);
    }
}
