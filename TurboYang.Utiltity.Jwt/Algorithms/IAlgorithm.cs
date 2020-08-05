using System;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public interface IAlgorithm
    {
        String Name { get; }
        Byte[] Sign(Byte[] data);
        Boolean VerifySignature(Byte[] data, Byte[] signature);
    }
}
