using System;
using System.Collections.Generic;
using System.Text;
using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public class JwtBuilder : IBuilder, IAsymmetricAlgorithmBuilder, ISymmetricAlgorithmBuilder, IAlgorithmWithKeyBuilder
    {
        private IAlgorithm Algorithm { get; set; }

        private JwtBuilder()
        {
        }

        public static IBuilder Create()
        {
            return new JwtBuilder();
        }

        #region Symmetric Algorithm

        private Dictionary<SymmetricAlgorithmType, Type> SymmetricAlgorithmDictionary { get; } = new Dictionary<SymmetricAlgorithmType, Type>()
        {
            { SymmetricAlgorithmType.HS256, typeof(Hs256Algorithm) },
            { SymmetricAlgorithmType.HS384, typeof(Hs384Algorithm) },
            { SymmetricAlgorithmType.HS512, typeof(Hs512Algorithm) },
        };

        public ISymmetricAlgorithmBuilder WithAlgorithm(SymmetricAlgorithmType algorithmType)
        {
            Algorithm = Activator.CreateInstance(SymmetricAlgorithmDictionary[algorithmType], true) as IAlgorithm;

            return this;
        }

        public IAlgorithmWithKeyBuilder WithKey(String key)
        {
            return WithKey(Encoding.UTF8.GetBytes(key));
        }

        public IAlgorithmWithKeyBuilder WithKey(Byte[] key)
        {
            ((SymmetricAlgorithm)Algorithm).Key = key;

            return this;
        }

        #endregion

        #region Asymmetric Algorithm

        private Dictionary<AsymmetricAlgorithmType, Type> AsymmetricAlgorithmDictionary { get; } = new Dictionary<AsymmetricAlgorithmType, Type>()
        {
            { AsymmetricAlgorithmType.RS256, typeof(Rs256Algorithm) },
            { AsymmetricAlgorithmType.RS384, typeof(Rs384Algorithm) },
            { AsymmetricAlgorithmType.RS512, typeof(Rs512Algorithm) },
            { AsymmetricAlgorithmType.ES256, typeof(Es256Algorithm) },
            { AsymmetricAlgorithmType.ES384, typeof(Es384Algorithm) },
            { AsymmetricAlgorithmType.ES512, typeof(Es512Algorithm) },
            { AsymmetricAlgorithmType.PS256, typeof(Ps256Algorithm) },
            { AsymmetricAlgorithmType.PS384, typeof(Ps384Algorithm) },
            { AsymmetricAlgorithmType.PS512, typeof(Ps512Algorithm) },
        };

        public IAsymmetricAlgorithmBuilder WithAlgorithm(AsymmetricAlgorithmType algorithmType)
        {
            Algorithm = Activator.CreateInstance(AsymmetricAlgorithmDictionary[algorithmType], true) as IAlgorithm;

            return this;
        }

        public IAlgorithmWithKeyBuilder WithKey(IPemPrivateKey privateKey)
        {
            ((AsymmetricAlgorithm)Algorithm).PrivateKey = privateKey;

            return this;
        }

        public IAlgorithmWithKeyBuilder WithKey(IPemPublicKey publicKey)
        {
            ((AsymmetricAlgorithm)Algorithm).PublicKey = publicKey;

            return this;
        }

        public IAlgorithmWithKeyBuilder WithKeys(PemKeyPair keyPair)
        {
            ((AsymmetricAlgorithm)Algorithm).PublicKey = (PemPublicKey)keyPair.PublicKey;
            ((AsymmetricAlgorithm)Algorithm).PrivateKey = (PemPrivateKey)keyPair.PrivateKey;

            return this;
        }

        public IAlgorithmWithKeyBuilder WithPrivateKey(String privateKey)
        {
            ((AsymmetricAlgorithm)Algorithm).PrivateKey = (PemPrivateKey)privateKey;

            return this;
        }

        public IAlgorithmWithKeyBuilder WithPublicKey(String publicKey)
        {
            ((AsymmetricAlgorithm)Algorithm).PublicKey = (PemPublicKey)publicKey;

            return this;
        }

        #endregion

        #region None Algorithm

        public IAlgorithmWithKeyBuilder WithAlgorithm(NoneAlgorithmType algorithmType)
        {
            Algorithm = new NoneAlgorithm();

            return this;
        }

        #endregion

        public Byte[] Decode(String jwtString)
        {
            return new JwtHandler().Decode(jwtString, Algorithm);
        }

        public T Decode<T>(String jwtString)
        {
            return new JwtHandler().Decode<T>(jwtString, Algorithm);
        }

        public String Encode(Byte[] payload)
        {
            return new JwtHandler().Encode(payload, Algorithm);
        }

        public String Encode<T>(T payload)
        {
            return new JwtHandler().Encode(payload, Algorithm);
        }
    }
}
