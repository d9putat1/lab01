using System.Net;
using System.Net.Http.Json;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// A-11: власні endpoint-и ЛР 1–2 (search, severity-summary) обмежені дозволеною множиною.
public sealed class SearchAndSummaryScopingTests(LoggedInUsersFixture users)
    : IClassFixture<LoggedInUsersFixture>
{
    private static readonly Guid BobNewIncidentId =
        Guid.Parse("20000000-0000-0000-0000-000000000004");

    private static string BobQuery => "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien");

    [Fact]
    public async Task Search_Anonymous_Returns401()
    {
        using var anonymous = users.Factory.CreateClient();

        using var response = await anonymous.GetAsync("/api/incidents/search?q=USB");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Search_AsReporter_DoesNotReturnForeignIncident()
    {
        var items = await users.Alice.GetFromJsonAsync<List<IncidentSearchItemResponse>>(BobQuery);

        Assert.NotNull(items);
        Assert.DoesNotContain(items, item => item.Id == BobNewIncidentId);
    }

    [Fact]
    public async Task Search_AsOwner_ReturnsOwnIncident()
    {
        var items = await users.Bob.GetFromJsonAsync<List<IncidentSearchItemResponse>>(BobQuery);

        Assert.NotNull(items);
        Assert.Contains(items, item => item.Id == BobNewIncidentId);
    }

    [Fact]
    public async Task Search_AsAnalyst_ReturnsIncidentsOfAllOwners()
    {
        var items = await users.Morgan.GetFromJsonAsync<List<IncidentSearchItemResponse>>(BobQuery);

        Assert.NotNull(items);
        Assert.Contains(items, item => item.Id == BobNewIncidentId);
    }

    [Fact]
    public async Task Search_AsAdministrator_DoesNotReturnForeignIncident()
    {
        var items = await users.Admin.GetFromJsonAsync<List<IncidentSearchItemResponse>>(
            "/api/incidents/search?q=USB");

        Assert.NotNull(items);
        Assert.Empty(items);
    }

    [Fact]
    public async Task Summary_AsReporter_CountsOnlyOwnIncidents()
    {
        var own = await users.Alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        var summary = await users.Alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.NotNull(own);
        Assert.NotNull(summary);
        Assert.Equal(own.Count, summary.Sum(item => item.Count));
        // Після reset Alice не має High; один High належить Bob і в її агрегат не потрапляє.
        Assert.Equal(0, summary.Single(item => item.Severity == "High").Count);
    }

    [Fact]
    public async Task Summary_AsAnalyst_CountsAllIncidents()
    {
        var all = await users.Morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        var summary = await users.Morgan.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.NotNull(all);
        Assert.NotNull(summary);
        Assert.Equal(all.Count, summary.Sum(item => item.Count));
        Assert.True(summary.Single(item => item.Severity == "High").Count >= 1);
    }
}