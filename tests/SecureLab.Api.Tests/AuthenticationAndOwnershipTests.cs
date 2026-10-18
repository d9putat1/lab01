using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationAndOwnershipTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static object ValidBody(string title) => new
    {
        title,
        description = "Опис для перевірки автентифікації та власника.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
    };

    private async Task<Guid> ReadOwnerAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking()
            .Where(item => item.Title == title)
            .Select(item => item.OwnerUserId)
            .SingleAsync();
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    // A-01: анонімний запит до захищеного endpoint -> 401, без redirect і без HTML.
    [Fact]
    public async Task AnonymousCreate_Returns401_WithoutRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await anonymous.PostAsJsonAsync("/api/incidents", ValidBody($"Anon-{Guid.NewGuid():N}"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02: login -> /api/me повертає verified поточного користувача без чутливих полів.
    [Fact]
    public async Task Login_Then_Me_ReturnsCurrentPrincipal()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        using var response = await client.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains(DbSeeder.AliceId.ToString(), json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("alice", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("passwordHash", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("securityStamp", json, StringComparison.OrdinalIgnoreCase);
    }

    // A-03 (добрий рівень): чинна cookie + підроблений X-Demo-UserId -> профіль не змінюється.
    [Fact]
    public async Task Me_WithForgedHeader_StillReturnsOwnPrincipal()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains(DbSeeder.AliceId.ToString(), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(DbSeeder.BobId.ToString(), json, StringComparison.OrdinalIgnoreCase);
    }

    // A-04 (добрий рівень): create без owner у DTO -> owner береться з principal.
    [Fact]
    public async Task Create_WithoutOwnerField_UsesPrincipalAsOwner()
    {
        using var client = await factory.LoginAsync("bob", StudyPassword);
        var title = $"A04-{Guid.NewGuid():N}";
        try
        {
            using var response = await client.PostAsJsonAsync("/api/incidents", ValidBody(title));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            Assert.Equal(DbSeeder.BobId, await ReadOwnerAsync(title));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-05: підроблений ownerUserId у JSON ігнорується, owner = Bob (не Alice).
    [Fact]
    public async Task Create_WithForgedOwnerField_OwnerIsStillPrincipal()
    {
        using var client = await factory.LoginAsync("bob", StudyPassword);
        var title = $"A05-{Guid.NewGuid():N}";
        try
        {
            using var response = await client.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "A-05: підроблений власник має бути проігнорований.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5),
                ownerUserId = DbSeeder.AliceId
            });
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            var owner = await ReadOwnerAsync(title);
            Assert.Equal(DbSeeder.BobId, owner);
            Assert.NotEqual(DbSeeder.AliceId, owner);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-06 (добрий рівень): після logout той самий клієнт отримує 401.
    [Fact]
    public async Task Logout_Then_ProtectedRequest_Returns401()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var before = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var after = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07 (добрий рівень): невідомий користувач і хибний пароль дають однаковий зовнішній результат.
    [Fact]
    public async Task Login_UnknownUser_And_WrongPassword_GiveIdenticalResult()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = $"nouser{Guid.NewGuid():N}", password = "WrongPass1!" });
        using var wrongPassword = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "DefinitelyWrong1!" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrongPassword.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.MediaType,
            wrongPassword.Content.Headers.ContentType?.MediaType);
    }

    // Rate limit (добрий рівень): окремий host, щоб лічильник не зачепив інші тести.
    [Fact]
    public async Task Login_RateLimit_Returns429_AfterTooManyAttempts()
    {
        await using var isolated = factory.WithWebHostBuilder(_ => { });
        using var client = isolated.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var statuses = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 11; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/api/auth/login",
                new { userName = "nouser", password = "WrongPass1!" });
            statuses.Add(response.StatusCode);
        }

        Assert.All(statuses.Take(10), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[10]);
    }
}