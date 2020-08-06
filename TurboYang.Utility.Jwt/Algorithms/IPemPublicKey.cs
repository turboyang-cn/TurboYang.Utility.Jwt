using System;
using System.Collections.Generic;
using System.Text;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public interface IPemPublicKey
    {
        String PublicKey { get; }
    }
}
