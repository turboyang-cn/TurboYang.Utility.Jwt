﻿using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public sealed class Ps512Algorithm : AsymmetricAlgorithm
    {
        internal Ps512Algorithm()
        {
        }

        public Ps512Algorithm(IPemPublicKey publicKey)
            : base(publicKey)
        {
        }

        public Ps512Algorithm(IPemPrivateKey privateKey)
            : base(privateKey)
        {
        }

        public Ps512Algorithm(String publicKey, String privateKey)
            : base(publicKey, privateKey)
        {
        }

        public Ps512Algorithm(PemKeyPair keyPair)
            : base(keyPair)
        {
        }

        public override String Name => "PS512";

        public override Byte[] Sign(Byte[] data)
        {
            using (TextReader reader = new StringReader(PrivateKey.PrivateKey))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;

                ISigner signer = SignerUtilities.GetSigner("SHA512withRSAAndMGF1");

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

                ISigner signer = SignerUtilities.GetSigner("SHA512withRSAAndMGF1");

                signer.Init(false, key);

                signer.BlockUpdate(data, 0, data.Length);

                return signer.VerifySignature(signature);
            }
        }
    }
}
