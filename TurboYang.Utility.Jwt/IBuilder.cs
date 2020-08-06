using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public interface IBuilder
    {
        ISymmetricAlgorithmBuilder WithAlgorithm(SymmetricAlgorithmType algorithmType);
        IAsymmetricAlgorithmBuilder WithAlgorithm(AsymmetricAlgorithmType algorithmType);
        IAlgorithmWithKeyBuilder WithAlgorithm(NoneAlgorithmType algorithmType);
    }
}
