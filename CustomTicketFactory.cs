using System.Security.Claims;
using System.Security.Principal;
using JWT.Extensions.AspNetCore.Factories;
using Microsoft.AspNetCore.Authentication;

internal class CustomTicketFactory : ITicketFactory
{
    public AuthenticationTicket CreateTicket(IIdentity identity, AuthenticationScheme scheme) =>
            new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                scheme.Name);
}