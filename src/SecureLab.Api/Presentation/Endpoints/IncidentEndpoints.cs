using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

            group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();
                    // PoC (vulnerable): завантаження лише за id, без ownership/role. Потрібен лише login.
        group.MapPut("/{id:guid}", UpdateAsync).RequireAuthorization();
        group.MapPost("/{id:guid}/triage", TriageAsync).RequireAuthorization();
        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }
    
    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        var summary = await queries.GetSeveritySummaryAsync(
            parsedStatus,
            httpContext.TraceIdentifier,
            cancellationToken);

        return Results.Ok(summary);
    }
    
        private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.NotFound();
        }

        if (request.Title is not null)
        {
            incident.Title = request.Title;
        }

        if (request.Description is not null)
        {
            incident.Description = request.Description;
        }

        // Дефект: severity змінюється зі звичайного update, без ролі й без правила «High/Critical → опис ≥ 40».
        if (Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
            && Enum.IsDefined(severity))
        {
            incident.Severity = severity;
        }

        // Дефект: protected status змінюється зі звичайного update.
        if (Enum.TryParse<IncidentStatus>(request.Status, ignoreCase: true, out var status)
            && Enum.IsDefined(status))
        {
            incident.Status = status;
        }

        // Дефект: власник береться з body.
        if (request.OwnerUserId is { } ownerUserId)
        {
            incident.OwnerUserId = ownerUserId;
        }

        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.NotFound();
        }

        if (!Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var actorId))
        {
            return Results.Challenge();
        }

        var now = DateTimeOffset.UtcNow;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = actorId,
            OldStatus = incident.Status,
            NewStatus = IncidentStatus.Triaged,
            Note = "PoC triage",
            CreatedAtUtc = now
        });
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }
}
