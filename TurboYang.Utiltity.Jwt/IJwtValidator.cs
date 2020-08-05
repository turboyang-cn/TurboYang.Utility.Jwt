using System;
using TurboYang.Utiltity.Jwt.Algorithms;

namespace TurboYang.Utiltity.Jwt
{
    public interface IJwtValidator
    {
        Boolean Validate(String jwtString, IAlgorithm algorithm);
    }
}
