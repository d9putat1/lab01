using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class IncidentCreateAndSearchTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
        
    [Fact]
    public async Task Post_WithInvalidSeverity_Returns400WithSeverityKey()
    {
        var body = new
        {
            title = $"Invalid-{Guid.NewGuid():N}",
            description = "Опис для перевірки некоректного severity.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json",
            response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"severity\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Post_WithDuplicateActiveTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Перший запис з цим title для T-03.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
using var client = await factory.LoginAsync("alice", StudyPassword);
        try
        {
            using var first = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
        }
    }

        [Fact]
    public async Task Search_WithSqliControlInput_ReturnsEmptySet()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        var items = await client.GetFromJsonAsync<List<IncidentSearchItemResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("zz-no-match' OR TRUE -- "));

        Assert.NotNull(items);
        Assert.Empty(items);
    }

    [Fact]
    public async Task Search_WithUsbQuery_ReturnsExactlyOneKnownRecord()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        var items = await client.GetFromJsonAsync<List<IncidentSearchItemResponse>>(
            "/api/incidents/search?q=USB");

        Assert.NotNull(items);
        var item = Assert.Single(items);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000005"), item.Id);
    }

    [Fact]
    public async Task Search_WithUnknownSortBy_Returns400()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync(
            "/api/incidents/search?q=USB&sortBy=price");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
    
    [Fact]
    public async Task Post_WithOverpostingFields_ServerAssignsOwnStatusAndId()
    {
        var requestedId = Guid.NewGuid();
        var body = new
        {
            title = $"Overposting-{Guid.NewGuid():N}",
            description = "Перевірка mass-assignment: зайві поля має ігнорувати контракт.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            id = requestedId,
            ownerUserId = Guid.NewGuid(),
            status = "Closed",
            createdAtUtc = DateTimeOffset.UtcNow.AddYears(-1)
        };
using var client = await factory.LoginAsync("alice", StudyPassword);

        using var response = await client.PostAsJsonAsync("/api/incidents", body);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        Assert.NotNull(created);
        Assert.NotEqual(requestedId, created!.Id);
        Assert.Equal("New", created.Status);
    }
}