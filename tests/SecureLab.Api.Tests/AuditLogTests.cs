
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class AuditLogTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // A-09: denied privileged action → безпечна audit-подія
    // з тим самим trace id, що й у відповіді.
    [Fact]
    public async Task Triage_DeniedForReporter_WritesSafeAuditEvent_WithSameTraceIdAsResponse()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException(
                "Set local SeedUsers__Password outside Git.");

        var provider = new CapturingLoggerProvider();

        await using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureLogging(logging =>
                logging.AddProvider(provider)));

        using var alice = host.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
                HandleCookies = true
            });

        using (var login = await alice.PostAsJsonAsync(
            "/api/auth/login",
            new { userName = "alice", password }))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        using var created = await alice.PostAsJsonAsync(
            "/api/incidents",
            new
            {
                title = $"A09-{Guid.NewGuid():N}",
                description = "Інцидент для перевірки audit-події відмови.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
            });

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var incidentId = (
            await created.Content.ReadFromJsonAsync<CreatedIncidentResponse>()
        )!.Id;

        try
        {
            using var response = await alice.PostAsync(
                $"/api/incidents/{incidentId}/triage",
                content: null);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

            var body = (
                await response.Content.ReadFromJsonAsync<JsonObject>()
            )!;

            var traceId = body["traceId"]!.GetValue<string>();

            var audit = Assert.Single(
                provider.Messages,
                message => message.Contains(
                    "authorization.denied",
                    StringComparison.Ordinal));

            Assert.Contains(
                $"subject={DbSeeder.AliceId}",
                audit,
                StringComparison.Ordinal);

            Assert.Contains(
                "action=incident.triage",
                audit,
                StringComparison.Ordinal);

            Assert.Contains(
                $"resource={incidentId}",
                audit,
                StringComparison.Ordinal);

            Assert.Contains(
                "result=denied",
                audit,
                StringComparison.Ordinal);

            Assert.Contains(
                $"traceId={traceId}",
                audit,
                StringComparison.Ordinal);

            Assert.DoesNotContain(
                password,
                audit,
                StringComparison.Ordinal);

            Assert.DoesNotContain(
                "cookie",
                audit,
                StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await using var scope = host.Services.CreateAsyncScope();

            var db = scope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            await db.Incidents
                .Where(item => item.Id == incidentId)
                .ExecuteDeleteAsync();
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName)
            => new CapturingLogger(Messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => messages.Enqueue(formatter(state, exception));
        }
    }
}
