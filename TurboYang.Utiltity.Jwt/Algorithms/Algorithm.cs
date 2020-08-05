using System;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public abstract class Algorithm : IAlgorithm
    {
        public abstract String Name { get; }

        public abstract Byte[] Sign(Byte[] data);

        public abstract Boolean VerifySignature(Byte[] data, Byte[] signature);
    }
}
