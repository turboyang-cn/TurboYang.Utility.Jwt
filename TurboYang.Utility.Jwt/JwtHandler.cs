using System;
using System.Text;
using System.Text.Json;
using TurboYang.Utility.Jwt.Algorithms;

namespace TurboYang.Utility.Jwt
{
    public sealed class JwtHandler : IJwtEncoder, IJwtDecoder, IJwtValidator
    {
        public String Encode(Byte[] payload, IAlgorithm algorithm)
        {
            try
            {
                JwtHeader header = new JwtHeader()
                {
                    Algorithm = algorithm.Name,
                };

                Byte[] dataToSign = Encoding.UTF8.GetBytes($"{Base64UrlConverter.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)))}.{Base64UrlConverter.Encode(payload)}");

                return $"{Encoding.UTF8.GetString(dataToSign)}.{Base64UrlConverter.Encode(algorithm.Sign(dataToSign))}";
            }
            catch
            {
                return null;
            }
        }

        public String Encode<T>(T payload, IAlgorithm algorithm)
        {
            try
            {
                return Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)), algorithm);
            }
            catch
            {
                return default;
            }
        }

        public Byte[] Decode(String jwtString, IAlgorithm algorithm)
        {
            try
            {
                if (!Validate(jwtString, algorithm))
                {
                    return default;
                }

                return Base64UrlConverter.Decode(jwtString.Split('.')[1]);
            }
            catch
            {
                return default;
            }
        }

        public T Decode<T>(String jwtString, IAlgorithm algorithm)
        {
            try
            {
                Byte[] payloadData = Decode(jwtString, algorithm);

                return JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(payloadData));
            }
            catch
            {
                return default;
            }
        }

        public Boolean Validate(String jwtString, IAlgorithm algorithm)
        {
            try
            {
                String[] jwtParts = jwtString.Split('.');

                if (jwtParts.Length != 3)
                {
                    return false;
                }

                JwtHeader header = JsonSerializer.Deserialize<JwtHeader>(Encoding.UTF8.GetString(Base64UrlConverter.Decode(jwtParts[0])));

                if (header.Algorithm != algorithm.Name)
                {
                    return false;
                }

                return algorithm.VerifySignature(Encoding.UTF8.GetBytes($"{jwtParts[0]}.{jwtParts[1]}"), Base64UrlConverter.Decode(jwtParts[2]));
            }
            catch
            {
                return false;
            }
        }
    }
}
