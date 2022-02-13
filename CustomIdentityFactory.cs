using System.Security.Claims;
using System.Security.Principal;
using JWT.Extensions.AspNetCore;
using JWT.Extensions.AspNetCore.Factories;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

internal class CustomIdentityFactory : IIdentityFactory
{
    private readonly IOptionsMonitor<JwtAuthenticationOptions> _options;

    public CustomIdentityFactory(IOptionsMonitor<JwtAuthenticationOptions> options) =>
        _options = options;

    public IIdentity CreateIdentity(Type type, object payload)
    {
        var data = payload as Dictionary<string, object>;
        IEnumerable<Claim> claims = GetClaims(data);
        return _options.CurrentValue.IncludeAuthenticationScheme ?
            new ClaimsIdentity(claims, JwtAuthenticationDefaults.AuthenticationScheme) :
            new ClaimsIdentity(claims);
    }

    private IEnumerable<Claim> GetClaims(Dictionary<string, object>? payload)
    {
        if (payload is null)
        {
            yield break;
        }
        foreach (var p in payload)
        {
            if (p.Value is String value)
            {
                yield return new Claim(p.Key, value);
            }
            if (p.Value is JToken arr && arr.HasValues)
            {
                foreach (var item in arr.Values<string>())
                {
                    yield return new Claim(p.Key, item);
                }
            }
        }
    }
}