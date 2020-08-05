using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace TurboYang.Utiltity.Jwt
{
    public sealed class JwtHeader
    {
        [JsonProperty("alg")]
        public String Algorithm { get; set; }
        [JsonProperty("typ")]
        public String Type { get; } = "JWT";
    }
}
