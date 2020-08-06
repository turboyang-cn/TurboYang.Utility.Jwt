using System;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public interface IAlgorithm
    {
        String Name { get; }
        Byte[] Sign(Byte[] data);
        Boolean VerifySignature(Byte[] data, Byte[] signature);
    }
}
