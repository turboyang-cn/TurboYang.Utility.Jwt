using System;
using System.Collections.Generic;
using System.Text;
using TurboYang.Utiltity.Jwt.Algorithms;

namespace TurboYang.Utiltity.Jwt
{
    public interface IBuilder
    {
        ISymmetricAlgorithmBuilder WithAlgorithm(SymmetricAlgorithmType algorithmType);
        IAsymmetricAlgorithmBuilder WithAlgorithm(AsymmetricAlgorithmType algorithmType);
        IAlgorithmWithKeyBuilder WithAlgorithm(NoneAlgorithmType algorithmType);
    }
}
