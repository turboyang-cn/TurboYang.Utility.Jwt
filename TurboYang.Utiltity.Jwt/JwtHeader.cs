using System;
using System.Text.Json.Serialization;

namespace TurboYang.Utiltity.Jwt
{
    public sealed class JwtHeader
    {
        [JsonPropertyName("alg")]
        public String Algorithm { get; set; }
        [JsonPropertyName("typ")]
        public String Type { get; } = "JWT";
    }
}
