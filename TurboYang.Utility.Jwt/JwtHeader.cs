using System;
using System.Text.Json.Serialization;

namespace TurboYang.Utility.Jwt
{
    public sealed class JwtHeader
    {
        [JsonPropertyName("alg")]
        public String Algorithm { get; set; }
        [JsonPropertyName("typ")]
        public String Type { get; } = "JWT";
    }
}
