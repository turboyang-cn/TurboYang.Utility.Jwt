using System;
using TurboYang.Utiltity.Jwt.Algorithms;

namespace TurboYang.Utiltity.Jwt
{
    public interface IJwtEncoder
    {
        String Encode(Byte[] payload, IAlgorithm algorithm);

        String Encode<T>(T payload, IAlgorithm algorithm);
    }
}
