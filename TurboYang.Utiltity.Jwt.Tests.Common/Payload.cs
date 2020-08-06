using System;
using System.Text.Json.Serialization;

namespace TurboYang.Utiltity.Jwt.Tests.Common
{
    public sealed class Payload
    {
        [JsonPropertyName("username")]
        public String Username { get; set; }
    }
}
