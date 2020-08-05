using System;
using Newtonsoft.Json;

namespace TurboYang.Utiltity.Jwt.Tests.Common
{
    public sealed class Payload
    {
        [JsonProperty("username")]
        public String Username { get; set; }
    }
}
