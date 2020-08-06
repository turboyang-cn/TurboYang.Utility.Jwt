using System;

namespace TurboYang.Utility.Jwt
{
    public static class Base64UrlConverter
    {
        public static String Encode(Byte[] data)
        {
            return Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        public static Byte[] Decode(String data)
        {
            String base64String = data.Replace('-', '+').Replace('_', '/');

            switch (base64String.Length % 4)
            {
                case 2:
                    {
                        base64String += "==";
                        break;
                    }
                case 3:
                    {
                        base64String += "=";
                        break;
                    }
            }

            return Convert.FromBase64String(base64String);
        }
    }
}
