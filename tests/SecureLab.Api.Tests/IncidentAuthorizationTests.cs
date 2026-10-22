using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 4. Ідентифікатори A-xx — з таблиці методички ЛР 4 (не плутати з A-xx у тестах ЛР 3).
public sealed class IncidentAuthorizationTests(LoggedInUsersFixture users)
    : IClassFixture<LoggedInUsersFixture>
{
    private static readonly Guid BobNewIncidentId =
        Guid.Parse("20000000-0000-0000-0000-000000000004");

    // ---------- helpers ----------

    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "Навчальний інцидент для перевірки авторизації за володінням ресурсом.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        return created!.Id;
    }

    private async Task DeleteByIdAsync(Guid id)
    {
        await using var scope = users.Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }

    private static async Task<JsonObject> ReadDetailsAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonObject>())!;
    }

    // Знімок стану ресурсу для порівняння «до/після».
    private static string Snapshot(JsonObject details) => string.Join(
        '|',
        details["title"]!.GetValue<string>(),
        details["description"]!.GetValue<string>(),
        details["severity"]!.GetValue<string>(),
        details["status"]!.GetValue<string>());

    private static async Task<(HttpStatusCode Status, string? ContentType, JsonObject Body)> ReadProblemAsync(
        HttpResponseMessage response)
    {
        var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        // Єдина дозволена відмінність відповідей — поля кореляції запиту.
        body.Remove("traceId");
        body.Remove("requestId");
        return (response.StatusCode, response.Content.Headers.ContentType?.ToString(), body);
    }

    // ---------- A-01: анонім → 401, без redirect ----------

    [Theory]
    [InlineData("/api/incidents")]
    [InlineData("/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("/api/incidents/severity-summary")]
    [InlineData("/api/incident-comments/30000000-0000-0000-0000-000000000002")]
    public async Task ProtectedRead_Anonymous_Returns401_WithoutRedirect(string path)
    {
        using var anonymous = users.Factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await anonymous.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("PUT", "")]
    [InlineData("DELETE", "")]
    [InlineData("POST", "/triage")]
    public async Task Mutations_Anonymous_Return401_WithoutRedirect(string method, string suffix)
    {
        using var anonymous = users.Factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        // Випадковий id: якщо захист зламано, відповідь буде 404, а не знищення seed-даних.
        using var request = new HttpRequestMessage(
            new HttpMethod(method), $"/api/incidents/{Guid.NewGuid()}{suffix}");
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(new { title = "x", description = "y" });
        }

        using var response = await anonymous.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ---------- A-02: власний ресурс → allow ----------

    [Fact]
    public async Task Details_AsOwner_ReturnsOwnIncident()
    {
        var details = await ReadDetailsAsync(users.Alice, DbSeeder.AliceIncidentId);

        Assert.Equal(DbSeeder.AliceIncidentId, Guid.Parse(details["id"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Update_AsOwner_Returns200_AndChangesOnlyContent()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A02-{Guid.NewGuid():N}");
        var newTitle = $"A02-edited-{Guid.NewGuid():N}";
        try
        {
            using var response = await users.Alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = newTitle,
                description = "Оновлений власником опис інциденту для перевірки дозволеної зміни."
            });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var after = await ReadDetailsAsync(users.Alice, id);
            Assert.Equal(newTitle, after["title"]!.GetValue<string>());
            Assert.Equal("New", after["status"]!.GetValue<string>());
            Assert.Equal("Low", after["severity"]!.GetValue<string>());
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    [Fact]
    public async Task Delete_AsOwner_OfNewIncident_Returns204_AndResourceIsGone()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A02D-{Guid.NewGuid():N}");
        try
        {
            using var response = await users.Alice.DeleteAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

            using var after = await users.Alice.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NotFound, after.StatusCode);
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    [Fact]
    public async Task Delete_AsOwner_AfterTriage_Returns403_AndResourceStillExists()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A02T-{Guid.NewGuid():N}");
        try
        {
            using var triage = await users.Morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.OK, triage.StatusCode);

            using var response = await users.Alice.DeleteAsync($"/api/incidents/{id}");

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var after = await ReadDetailsAsync(users.Alice, id);
            Assert.Equal("Triaged", after["status"]!.GetValue<string>());
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    // ---------- A-03: Alice (non-owner Reporter) → Bob resource → 404, дані не потрапляють у відповідь ----------

    [Fact]
    public async Task Details_AsNonOwnerReporter_Returns404_AndDoesNotLeakBobData()
    {
        using var response = await users.Alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.Equal("Інцидент не знайдено", body["title"]!.GetValue<string>());
        Assert.False(body.ContainsKey("description"));
        Assert.False(body.ContainsKey("ownerDisplayName"));
        Assert.False(body.ContainsKey("comments"));
        Assert.False(body.ContainsKey("detail"));

        var raw = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), raw, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- A-03R: Morgan (Analyst) → details Alice/Bob → allow; довільної mutation немає ----------

    [Fact]
    public async Task Details_AsAnalyst_ReturnsIncidentsOfBothReporters()
    {
        var alices = await ReadDetailsAsync(users.Morgan, DbSeeder.AliceIncidentId);
        var bobs = await ReadDetailsAsync(users.Morgan, DbSeeder.BobIncidentId);

        Assert.Equal(DbSeeder.AliceIncidentId, Guid.Parse(alices["id"]!.GetValue<string>()));
        Assert.Equal(DbSeeder.BobIncidentId, Guid.Parse(bobs["id"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Update_AsAnalyst_Returns403_AndDoesNotChangeIncident()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A03R-{Guid.NewGuid():N}");
        try
        {
            var before = Snapshot(await ReadDetailsAsync(users.Alice, id));

            using var response = await users.Morgan.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = $"changed-by-analyst-{Guid.NewGuid():N}",
                description = "Analyst не має права довільно змінювати вміст чужого інциденту."
            });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal(before, Snapshot(await ReadDetailsAsync(users.Alice, id)));
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    [Fact]
    public async Task Delete_AsAnalyst_Returns403_AndIncidentStillExists()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A03RD-{Guid.NewGuid():N}");
        try
        {
            using var response = await users.Morgan.DeleteAsync($"/api/incidents/{id}");

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            _ = await ReadDetailsAsync(users.Alice, id);
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    // ---------- A-04: Alice → Bob update/delete → deny, стан Bob без змін ----------

    [Fact]
    public async Task Update_AsNonOwner_Returns404_AndDoesNotChangeResource()
    {
        var before = Snapshot(await ReadDetailsAsync(users.Bob, DbSeeder.BobIncidentId));

        using var response = await users.Alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "changed-by-alice", description = "Alice не має права змінювати чужий інцидент." });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(before, Snapshot(await ReadDetailsAsync(users.Bob, DbSeeder.BobIncidentId)));
    }

    [Fact]
    public async Task Update_AsNonOwner_WithInvalidBody_Returns404_NotValidationError()
    {
        // Права перевіряються РАНІШЕ за валідацію: чужий запит не повинен дізнатись про існування ресурсу.
        using var response = await users.Alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "", description = "" });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Delete_AsNonOwner_Returns404_AndResourceStillExists()
    {
        using var response = await users.Alice.DeleteAsync($"/api/incidents/{BobNewIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        // Стан читає власник Bob: Alice цього ресурсу не бачить.
        _ = await ReadDetailsAsync(users.Bob, BobNewIncidentId);
    }

    // ---------- A-05: list — лише дозволена множина ----------

    [Fact]
    public async Task List_AsReporter_ContainsOnlyOwnIncidents()
    {
        var items = await users.Alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(items);
        Assert.Contains(items, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(items, item => item.Id == DbSeeder.BobIncidentId);
        Assert.DoesNotContain(items, item => item.Id == BobNewIncidentId);
    }

    [Fact]
    public async Task List_AsAnalyst_ContainsIncidentsOfAllOwners()
    {
        var items = await users.Morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(items);
        Assert.Contains(items, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(items, item => item.Id == DbSeeder.BobIncidentId);
    }

    // ---------- Least privilege: Administrator без обходу ownership ----------

    [Fact]
    public async Task Details_AsAdministrator_OfForeignIncident_Returns404()
    {
        using var response = await users.Admin.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task List_AsAdministrator_ContainsNoForeignIncidents()
    {
        var items = await users.Admin.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(items);
        Assert.DoesNotContain(items, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(items, item => item.Id == DbSeeder.BobIncidentId);
    }

    // ---------- A-06: вертикальне підвищення заборонено ----------

    [Fact]
    public async Task Triage_AsReporterOwner_Returns403_AndDoesNotChangeStatus()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A06-{Guid.NewGuid():N}");
        try
        {
            using var response = await users.Alice.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var after = await ReadDetailsAsync(users.Alice, id);
            Assert.Equal("New", after["status"]!.GetValue<string>());
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    [Fact]
    public async Task Triage_AsNonOwnerReporter_Returns404_AndDoesNotChangeStatus()
    {
        // Seed-інцидент 3 належить Alice й має статус New; Bob його не бачить.
        using var response = await users.Bob.PostAsync(
            $"/api/incidents/{DbSeeder.SafeTextIncidentId}/triage", content: null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var after = await ReadDetailsAsync(users.Alice, DbSeeder.SafeTextIncidentId);
        Assert.Equal("New", after["status"]!.GetValue<string>());
    }

    // ---------- A-07: дозволена привілейована дія ----------

    [Fact]
    public async Task Triage_AsAnalyst_MovesNewToTriaged_AndRecordsHistory()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A07-{Guid.NewGuid():N}");
        try
        {
            using var response = await users.Morgan.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
            Assert.Equal("Triaged", body["status"]!.GetValue<string>());

            var after = await ReadDetailsAsync(users.Alice, id);
            Assert.Equal("Triaged", after["status"]!.GetValue<string>());

            await using var scope = users.Factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var history = await db.IncidentStatusHistory.AsNoTracking()
                .Where(item => item.IncidentId == id)
                .SingleAsync();
            Assert.Equal(IncidentStatus.New, history.OldStatus);
            Assert.Equal(IncidentStatus.Triaged, history.NewStatus);
            Assert.Equal(DbSeeder.MorganId, history.ChangedByUserId);
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }

    [Fact]
    public async Task Triage_AsAnalyst_OnNonNewIncident_Returns409_AndKeepsStatus()
    {
        // Seed-інцидент Bob має статус InProgress: допустимий лише перехід New → Triaged.
        using var response = await users.Morgan.PostAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}/triage", content: null);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var after = await ReadDetailsAsync(users.Bob, DbSeeder.BobIncidentId);
        Assert.Equal("InProgress", after["status"]!.GetValue<string>());
    }

    // ---------- A-08a: forged owner/role/status у звичайному update ігноруються ----------

    [Fact]
    public async Task Update_WithForgedProtectedFields_IgnoresThem_AndChangesOnlyContent()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A08-{Guid.NewGuid():N}");
        var newTitle = $"A08-edited-{Guid.NewGuid():N}";
        try
        {
            using var response = await users.Alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = newTitle,
                description = "Оновлений опис без права змінювати захищений стан.",
                ownerUserId = DbSeeder.BobId,
                status = "Closed",
                severity = "Critical",
                role = "Administrator",
                isTransitionAllowed = true
            });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            await using var scope = users.Factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var stored = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == id);

            Assert.Equal(newTitle, stored.Title);                       // дозволений content змінився
            Assert.Equal(DbSeeder.AliceId, stored.OwnerUserId);         // owner не змінився
            Assert.Equal(IncidentStatus.New, stored.Status);            // protected status не змінився
            Assert.Equal(IncidentSeverity.Low, stored.Severity);        // severity не змінився
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }
    // A-08a (severity): Reporter не може підняти пріоритет власного інциденту звичайним update.
    [Fact]
    public async Task Update_WithForgedSeverity_DoesNotEscalateIncident()
    {
        var id = await CreateIncidentAsync(users.Alice, $"A08S-{Guid.NewGuid():N}");
        try
        {
            using var response = await users.Alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = $"A08S-edited-{Guid.NewGuid():N}",
                description = "x",
                severity = "Critical"
            });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var after = await ReadDetailsAsync(users.Alice, id);
            Assert.Equal("Low", after["severity"]!.GetValue<string>());
            Assert.Equal("New", after["status"]!.GetValue<string>());
        }
        finally
        {
            await DeleteByIdAsync(id);
        }
    }
    // ---------- A-10: чужий і неіснуючий id нерозрізнювані (політика 404) ----------

    [Fact]
    public async Task Details_ForeignAndUnknownId_AreIndistinguishable()
    {
        using var foreign = await users.Alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await users.Alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        var foreignProblem = await ReadProblemAsync(foreign);
        var unknownProblem = await ReadProblemAsync(unknown);

        Assert.Equal(HttpStatusCode.NotFound, foreignProblem.Status);
        Assert.Equal(unknownProblem.Status, foreignProblem.Status);
        Assert.Equal(unknownProblem.ContentType, foreignProblem.ContentType);
        Assert.True(JsonNode.DeepEquals(unknownProblem.Body, foreignProblem.Body));
    }

    [Fact]
    public async Task Update_ForeignAndUnknownId_AreIndistinguishable()
    {
        var body = new { title = "same body", description = "Однаковий за структурою запит." };

        using var foreign = await users.Alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}", body);
        using var unknown = await users.Alice.PutAsJsonAsync($"/api/incidents/{Guid.NewGuid()}", body);

        var foreignProblem = await ReadProblemAsync(foreign);
        var unknownProblem = await ReadProblemAsync(unknown);

        Assert.Equal(HttpStatusCode.NotFound, foreignProblem.Status);
        Assert.Equal(unknownProblem.Status, foreignProblem.Status);
        Assert.Equal(unknownProblem.ContentType, foreignProblem.ContentType);
        Assert.True(JsonNode.DeepEquals(unknownProblem.Body, foreignProblem.Body));
    }

    // ---------- A-12: child resource і internal comment ----------

    [Fact]
    public async Task Comment_OfForeignIncident_AsReporter_Returns404()
    {
        using var response = await users.Alice.GetAsync(
            $"/api/incident-comments/{DbSeeder.BobIncidentCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.False(body.ContainsKey("text"));
        Assert.False(body.ContainsKey("authorDisplayName"));
    }

    [Fact]
    public async Task InternalComment_AsOwnerReporter_Returns404_AndIsAbsentFromDetails()
    {
        using var direct = await users.Alice.GetAsync(
            $"/api/incident-comments/{DbSeeder.AliceInternalCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, direct.StatusCode);

        var details = await ReadDetailsAsync(users.Alice, DbSeeder.AliceIncidentId);
        var comments = details["comments"]!.AsArray();
        Assert.DoesNotContain(comments, comment => string.Equals(
            comment!["id"]!.GetValue<string>(),
            DbSeeder.AliceInternalCommentId.ToString(),
            StringComparison.OrdinalIgnoreCase));
        Assert.All(comments, comment =>
            Assert.DoesNotContain("Внутрішня", comment!["text"]!.GetValue<string>(), StringComparison.Ordinal));
    }

    [Fact]
    public async Task InternalComment_AsAnalyst_IsReadable_AndPresentInDetails()
    {
        using var direct = await users.Morgan.GetAsync(
            $"/api/incident-comments/{DbSeeder.AliceInternalCommentId}");
        Assert.Equal(HttpStatusCode.OK, direct.StatusCode);

        var details = await ReadDetailsAsync(users.Morgan, DbSeeder.AliceIncidentId);
        Assert.Contains(details["comments"]!.AsArray(), comment => string.Equals(
            comment!["id"]!.GetValue<string>(),
            DbSeeder.AliceInternalCommentId.ToString(),
            StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task PublicComment_AsOwnerReporter_OfOwnIncident_Returns200()
    {
        // comment-1: публічний коментар Morgan до інциденту Alice.
        using var response = await users.Alice.GetAsync(
            "/api/incident-comments/30000000-0000-0000-0000-000000000001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}