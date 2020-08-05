using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TurboYang.Utiltity.Jwt.Algorithms;
using TurboYang.Utiltity.Jwt.Tests.Common;

namespace TurboYang.Utiltity.Jwt.Tests.Net45
{
    [TestClass]
    public class JwtUnitTest
    {
        private Payload Payload { get; } = new Payload()
        {
            Username = "root"
        };

        [TestMethod]
        public void HS256AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(SymmetricAlgorithmType.HS256)
                                                  .WithKey(KeySet.Key)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(SymmetricAlgorithmType.HS256)
                                                 .WithKey(KeySet.Key)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void HS384AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(SymmetricAlgorithmType.HS384)
                                                  .WithKey(KeySet.Key)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(SymmetricAlgorithmType.HS384)
                                                 .WithKey(KeySet.Key)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void HS512AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(SymmetricAlgorithmType.HS512)
                                                  .WithKey(KeySet.Key)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(SymmetricAlgorithmType.HS512)
                                                 .WithKey(KeySet.Key)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void HS256Algorithm()
        {
            IAlgorithm algorithm = new Hs256Algorithm(KeySet.Key);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void HS384Algorithm()
        {
            IAlgorithm algorithm = new Hs384Algorithm(KeySet.Key);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void HS512Algorithm()
        {
            IAlgorithm algorithm = new Hs512Algorithm(KeySet.Key);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void RS256AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.RS256)
                                                  .WithKey((PemPrivateKey)KeySet.RsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.RS256)
                                                 .WithKey((PemPublicKey)KeySet.RsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void RS384AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.RS384)
                                                  .WithKey((PemPrivateKey)KeySet.RsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.RS384)
                                                 .WithKey((PemPublicKey)KeySet.RsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void RS512AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.RS512)
                                                  .WithKey((PemPrivateKey)KeySet.RsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.RS512)
                                                 .WithKey((PemPublicKey)KeySet.RsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void RS256Algorithm()
        {
            IAlgorithm algorithm = new Rs256Algorithm(KeySet.RsaPublicKey, KeySet.RsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void RS384Algorithm()
        {
            IAlgorithm algorithm = new Rs384Algorithm(KeySet.RsaPublicKey, KeySet.RsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void RS512Algorithm()
        {
            IAlgorithm algorithm = new Rs512Algorithm(KeySet.RsaPublicKey, KeySet.RsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void PS256AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.PS256)
                                                  .WithKey((PemPrivateKey)KeySet.RsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.PS256)
                                                 .WithKey((PemPublicKey)KeySet.RsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void PS384AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.PS384)
                                                  .WithKey((PemPrivateKey)KeySet.RsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.PS384)
                                                 .WithKey((PemPublicKey)KeySet.RsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void PS512AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.PS512)
                                                  .WithKey((PemPrivateKey)KeySet.RsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.PS512)
                                                 .WithKey((PemPublicKey)KeySet.RsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void PS256Algorithm()
        {
            IAlgorithm algorithm = new Ps256Algorithm(KeySet.RsaPublicKey, KeySet.RsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void PS384Algorithm()
        {
            IAlgorithm algorithm = new Ps384Algorithm(KeySet.RsaPublicKey, KeySet.RsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void PS512Algorithm()
        {
            IAlgorithm algorithm = new Ps512Algorithm(KeySet.RsaPublicKey, KeySet.RsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void ES256AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.ES256)
                                                  .WithKey((PemPrivateKey)KeySet.EcdsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.ES256)
                                                 .WithKey((PemPublicKey)KeySet.EcdsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void ES384AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.ES384)
                                                  .WithKey((PemPrivateKey)KeySet.EcdsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.ES384)
                                                 .WithKey((PemPublicKey)KeySet.EcdsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void ES512AlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.ES512)
                                                  .WithKey((PemPrivateKey)KeySet.EcdsaPrivateKey)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(AsymmetricAlgorithmType.ES512)
                                                 .WithKey((PemPublicKey)KeySet.EcdsaPublicKey)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void ES256Algorithm()
        {
            IAlgorithm algorithm = new Es256Algorithm(KeySet.EcdsaPublicKey, KeySet.EcdsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void ES384Algorithm()
        {
            IAlgorithm algorithm = new Es384Algorithm(KeySet.EcdsaPublicKey, KeySet.EcdsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void ES512Algorithm()
        {
            IAlgorithm algorithm = new Es512Algorithm(KeySet.EcdsaPublicKey, KeySet.EcdsaPrivateKey);

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void NoneAlgorithmFluentApi()
        {
            String jwtString = JwtBuilder.Create().WithAlgorithm(NoneAlgorithmType.None)
                                                  .Encode(Payload);

            Payload payload = JwtBuilder.Create().WithAlgorithm(NoneAlgorithmType.None)
                                                 .Decode<Payload>(jwtString);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }

        [TestMethod]
        public void NoneAlgorithm()
        {
            IAlgorithm algorithm = new NoneAlgorithm();

            JwtHandler jwtHandler = new JwtHandler();
            String jwtString = jwtHandler.Encode(Payload, algorithm);
            Payload payload = jwtHandler.Decode<Payload>(jwtString, algorithm);

            Assert.IsTrue(payload != null && Payload.Username == payload.Username);
        }
    }
}
