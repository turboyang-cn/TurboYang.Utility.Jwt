using System;
using System.Collections.Generic;
using System.Text;

namespace TurboYang.Utility.Jwt
{
    public interface IAlgorithmWithKeyBuilder
    {
        String Encode(Byte[] payload);
        String Encode<T>(T payload);
        Byte[] Decode(String jwtString);
        T Decode<T>(String jwtString);
    }
}
