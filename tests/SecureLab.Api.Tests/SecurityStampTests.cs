using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class SecurityStampTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task OldCookie_IsRejected_AfterSecurityStampUpdate()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

        // ValidationInterval = 0 лише в цьому тестовому host: перевірка stamp на кожному запиті,
        // інакше стандартна періодичність (30 хв) не дала б спостерігати ефект.
        await using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
                services.Configure<SecurityStampValidatorOptions>(options =>
                    options.ValidationInterval = TimeSpan.Zero)));

        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

        using var before = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var alice = await users.FindByNameAsync("alice");
            Assert.NotNull(alice);
            await users.UpdateSecurityStampAsync(alice!);
        }

        using var after = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }
}