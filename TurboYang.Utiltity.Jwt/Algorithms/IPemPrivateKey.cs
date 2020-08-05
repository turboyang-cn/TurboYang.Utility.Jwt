using System;
using System.Collections.Generic;
using System.Text;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public interface IPemPrivateKey
    {
        String PrivateKey { get; }
    }
}
