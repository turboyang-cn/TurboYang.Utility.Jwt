using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public static class RsKeyPairGenerator
    {
        public static PemKeyPair GenerateKeyPair()
        {
            String privateKey = String.Empty;
            String publicKey = String.Empty;

            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));

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
