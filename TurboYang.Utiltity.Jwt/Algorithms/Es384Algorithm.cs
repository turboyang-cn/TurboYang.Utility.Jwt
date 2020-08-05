using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace TurboYang.Utiltity.Jwt.Algorithms
{
    public sealed class Es384Algorithm : AsymmetricAlgorithm
    {
        internal Es384Algorithm()
        {
        }

        public Es384Algorithm(IPemPublicKey publicKey)
            : base(publicKey)
        {
        }

        public Es384Algorithm(IPemPrivateKey privateKey)
            : base(privateKey)
        {
        }

        public Es384Algorithm(String publicKey, String privateKey)
            : base(publicKey, privateKey)
        {
        }

        public Es384Algorithm(PemKeyPair keyPair)
            : base(keyPair)
        {
        }

        public override String Name => "ES384";

        public override Byte[] Sign(Byte[] data)
        {
            using (TextReader reader = new StringReader(PrivateKey.PrivateKey))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;

                ISigner signer = SignerUtilities.GetSigner("SHA384withECDSA");

                signer.Init(true, keyPair.Private);

                signer.BlockUpdate(data, 0, data.Length);

                return signer.GenerateSignature();
            }
        }

        public override Boolean VerifySignature(Byte[] data, Byte[] signature)
        {
            using (TextReader reader = new StringReader(PublicKey.PublicKey))
            {
                PemReader pemReader = new PemReader(reader);
                ECPublicKeyParameters key = pemReader.ReadObject() as ECPublicKeyParameters;

                ISigner signer = SignerUtilities.GetSigner("SHA384withECDSA");

                signer.Init(false, key);

                signer.BlockUpdate(data, 0, data.Length);

                return signer.VerifySignature(signature);
            }
        }
    }
}
