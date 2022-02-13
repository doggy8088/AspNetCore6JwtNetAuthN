using System.Security.Claims;
using System.Security.Principal;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Extensions.AspNetCore;
using JWT.Extensions.AspNetCore.Factories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.Configure<JwtSettingsOptions>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.AddOptions<JwtSettingsOptions>("JwtSettings");
builder.Services.AddSingleton<JwtHelpers>();
builder.Services.AddSingleton<IAlgorithmFactory>(new DelegateAlgorithmFactory(new HMACSHA256Algorithm()));

builder.Services.AddSingleton<IIdentityFactory, CustomIdentityFactory>();
// builder.Services.AddSingleton<ITicketFactory, CustomTicketFactory>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
    })
    .AddJwt(options =>
    {
        options.PayloadType = typeof(Dictionary<string, object>);
        options.Keys = new string[] { builder.Configuration.GetValue<string>("JwtSettings:SignKey") };
        options.VerifySignature = true;
    });

builder.Services.AddAuthorization();

// builder.Services.AddAuthorization(options => {
//     options.AddPolicy("AdminOnly", policy => policy.RequireClaim("admin", "true"));
// });


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateTime.Now.AddDays(index),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
            .ToArray();
        return forecast;
    })
    .WithName("GetWeatherForecast");

app.MapPost("/signin", (LoginViewModel login, JwtHelpers jwt) =>
    {
        if (ValidateUser(login))
        {
            var token = jwt.GenerateToken(login.Username);
            return Results.Ok(new { token });
        }
        else
        {
            return Results.BadRequest();
        }
    })
    .WithName("SignIn")
    .AllowAnonymous();

app.MapGet("/claims", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Claims.Select(p => new { p.Type, p.Value }));
    })
    .WithName("Claims")
    .RequireAuthorization();

app.MapGet("/username", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Identity?.Name);
    })
    .WithName("Username")
    .RequireAuthorization();

app.MapGet("/isInRole", (ClaimsPrincipal user, string name) =>
    {
        return Results.Ok(user.IsInRole(name));
    })
    .WithName("IsInRole")
    .RequireAuthorization();

app.MapGet("/jwtid", (ClaimsPrincipal user) =>
    {
        return Results.Ok(user.Claims.FirstOrDefault(p => p.Type == "jti")?.Value);
    })
    .WithName("JwtId")
    .RequireAuthorization();

app.Run();

bool ValidateUser(LoginViewModel login)
{
    return true;
}

record LoginViewModel(string Username, string Password);

// Not working
// public record JwtSettingsOptions(string Issuer = default, string SignKey = default);

// Too messy
// public record JwtSettingsOptions(string Issuer, string SignKey)
// {
//     public JwtSettingsOptions() : this("", "") {}
// }

public class JwtSettingsOptions
{
    public string Issuer { get; set; } = "";
    public string SignKey { get; set; } = "";
}

record WeatherForecast(DateTime Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public class JwtHelpers
{
    private readonly JwtSettingsOptions settings;

    public JwtHelpers(IOptions<JwtSettingsOptions> settings)
    {
        this.settings = settings.Value;
    }

    public string GenerateToken(string userName, int expireMinutes = 30)
    {
        var issuer = settings.Issuer;
        var signKey = settings.SignKey;

        var token = JwtBuilder.Create()
                        .WithAlgorithm(new HMACSHA256Algorithm()) // symmetric
                        .WithSecret(signKey)
                        // 在 RFC 7519 規格中(Section#4)，總共定義了 7 個預設的 Claims，我們應該只用的到兩種！
                        .AddClaim("jti", Guid.NewGuid().ToString()) // JWT ID
                        .AddClaim("iss", issuer)
                        // .AddClaim("nameid", userName) // User.Identity.Name
                        .AddClaim("sub", userName) // User.Identity.Name
                        // .AddClaim("aud", "The Audience") // 由於你的 API 受眾通常沒有區分特別對象，因此通常不太需要設定，也不太需要驗證
                        .AddClaim("exp", DateTimeOffset.UtcNow.AddMinutes(expireMinutes).ToUnixTimeSeconds())
                        .AddClaim("nbf", DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                        .AddClaim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                        // .AddClaim("roles", new string[] { "Admin", "Users" })
                        .AddClaim(ClaimTypes.Role, new string[] { "Admin", "Users" })
                        .AddClaim(ClaimTypes.Name, userName)
                        .Encode();
        return token;
    }
}
