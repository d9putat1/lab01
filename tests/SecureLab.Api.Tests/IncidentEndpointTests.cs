using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentEndpointTests(LoggedInUsersFixture users)
    : IClassFixture<LoggedInUsersFixture>
{
    // Було: список містив і Alice, і Bob. За матрицею Reporter бачить лише власні інциденти (A-05).
    [Fact]
    public async Task GetList_ReturnsOnlyIncidentsAllowedForCurrentUser()
    {
        var incidents = await users.Alice.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var response = await users.Alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var response = await users.Alice.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        // Статичні файли не захищені авторизацією: клієнт вантажиться без login.
        using var anonymous = users.Factory.CreateClient();
        var script = await anonymous.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetSeveritySummary_ReturnsFullSeverityList()
    {
        var summary = await users.Alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.NotNull(summary);
        Assert.Equal(4, summary.Count);
        Assert.Contains(summary, item => item.Severity == "Critical" && item.Count == 0);
    }

    [Fact]
    public async Task GetSeveritySummary_ForInvalidStatus_ReturnsValidationProblem400()
    {
        using var response = await users.Alice.GetAsync(
            "/api/incidents/severity-summary?status=Unknown");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetSeveritySummary_FilteredByClosedStatus_AllCountsAreZero()
    {
        var summary = await users.Alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary?status=Closed");

        Assert.NotNull(summary);
        Assert.All(summary, item => Assert.Equal(0, item.Count));
    }
}