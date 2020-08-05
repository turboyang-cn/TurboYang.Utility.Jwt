using System;
using TurboYang.Utiltity.Jwt.Algorithms;

namespace TurboYang.Utiltity.Jwt
{
    public interface IJwtDecoder
    {
        T Decode<T>(String jwtString, IAlgorithm algorithm);

        Byte[] Decode(String jwtString, IAlgorithm algorithm);
    }
}
