using System;
using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public interface IJwtDecoder
    {
        T Decode<T>(String jwtString, IAlgorithm algorithm);

        Byte[] Decode(String jwtString, IAlgorithm algorithm);
    }
}
