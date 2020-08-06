using System;
using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public interface IJwtEncoder
    {
        String Encode(Byte[] payload, IAlgorithm algorithm);

        String Encode<T>(T payload, IAlgorithm algorithm);
    }
}
