using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public sealed class Rs384Algorithm : AsymmetricAlgorithm
    {
        internal Rs384Algorithm()
        {
        }

        public Rs384Algorithm(IPemPublicKey publicKey)
            : base(publicKey)
        {
        }

        public Rs384Algorithm(IPemPrivateKey privateKey)
            : base(privateKey)
        {
        }

        public Rs384Algorithm(String publicKey, String privateKey)
            : base(publicKey, privateKey)
        {
        }

        public Rs384Algorithm(PemKeyPair keyPair)
            : base(keyPair)
        {
        }

        public override String Name => "RS384";

        public override Byte[] Sign(Byte[] data)
        {
            using (TextReader reader = new StringReader(PrivateKey.PrivateKey))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;

                ISigner signer = SignerUtilities.GetSigner("SHA384withRSA");

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
                RsaKeyParameters key = pemReader.ReadObject() as RsaKeyParameters;

                ISigner signer = SignerUtilities.GetSigner("SHA384withRSA");

                signer.Init(false, key);

                signer.BlockUpdate(data, 0, data.Length);

                return signer.VerifySignature(signature);
            }
        }
    }
}
