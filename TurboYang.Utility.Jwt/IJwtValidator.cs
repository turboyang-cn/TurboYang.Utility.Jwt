using System;
using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public interface IJwtValidator
    {
        Boolean Validate(String jwtString, IAlgorithm algorithm);
    }
}
