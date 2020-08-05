using System;
using System.IO;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public static class EcKeyPairGenerator
    {
        public static PemKeyPair GenerateKeyPair()
        {
            String privateKey = String.Empty;
            String publicKey = String.Empty;

            X9ECParameters ecParameters = ECNamedCurveTable.GetByName("secp256k1");

            ECKeyPairGenerator keyGenerator = new ECKeyPairGenerator();
            keyGenerator.Init(new ECKeyGenerationParameters(new ECDomainParameters(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H), new SecureRandom()));

            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            using (TextWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
                privateKey = writer.ToString();
            }

            using (TextWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(keyPair.Public);
                pemWriter.Writer.Flush();
                publicKey = writer.ToString();
            }

            return new PemKeyPair(publicKey, privateKey);
        }
    }
}
