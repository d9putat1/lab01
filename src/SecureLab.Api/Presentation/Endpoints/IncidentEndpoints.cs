using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Уся група вимагає автентифікації: анонімний запит отримує 401 ще до виконання endpoint.
        // Це лише перший бар'єр (хто ти), а не рішення про право на конкретний ресурс.
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

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

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .Produces<UpdatedIncidentResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces<TriageIncidentResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        return endpoints;
    }

    // Один helper для ВСІХ гілок «не знайдено»: невідомий id і чужий ресурс мають збігатися
    // за status, Content-Type і тілом (відрізняється лише traceId). Жодного detail з id.
    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
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

        // Гілка Challenge обробляє некоректний автентифікований контекст без придатного id;
        // вона НЕ замінює RequireAuthorization() на групі.
        if (!IncidentAccessPolicy.TryGetUserId(httpContext.User, out var userId))
        {
            return Results.Challenge();
        }

        var canReadAll = IncidentAccessPolicy.CanReadAll(httpContext.User);
        return Results.Ok(await queries.GetListAsync(parsedStatus, userId, canReadAll, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindForDecisionAsync(id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canReadInternal = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.ReadInternalComments);

        var details = await queries.GetDetailsAsync(id, canReadInternal.Succeeded, cancellationToken);
        return details is null ? IncidentNotFound() : Results.Ok(details);
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

        if (!IncidentAccessPolicy.TryGetUserId(httpContext.User, out var userId))
        {
            return Results.Challenge();
        }

        var canReadAll = IncidentAccessPolicy.CanReadAll(httpContext.User);
        var summary = await queries.GetSeveritySummaryAsync(
            parsedStatus,
            userId,
            canReadAll,
            httpContext.TraceIdentifier,
            cancellationToken);

        return Results.Ok(summary);
    }
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        // Tracked entity (БЕЗ AsNoTracking): інакше SaveChangesAsync нічого б не записав.
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canUpdate = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Update);
        if (!canUpdate.Succeeded)
        {
            return Results.Forbid();
        }

        // Валідація — ПІСЛЯ авторизації: чужий запит із поганим body має отримати ту саму 404, а не 400.
        var title = request.Title?.Trim() ?? string.Empty;
        var description = request.Description?.Trim() ?? string.Empty;
        var errors = new Dictionary<string, string[]>();

        if (title.Length == 0)
        {
            errors["title"] = ["Тема обов'язкова."];
        }
        else if (title.Length > 160)
        {
            errors["title"] = ["Тема не довша за 160 символів."];
        }

        if (description.Length == 0)
        {
            errors["description"] = ["Опис обов'язковий."];
        }
        else if (description.Length > 4000)
        {
            errors["description"] = ["Опис не довший за 4000 символів."];
        }
        else if ((incident.Severity is IncidentSeverity.High or IncidentSeverity.Critical)
            && description.Length < 40)
        {
            errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        var blockingStatuses = new[]
        {
            IncidentStatus.New, IncidentStatus.Triaged,
            IncidentStatus.InProgress, IncidentStatus.Resolved
        };
        var hasActiveDuplicate = await db.Incidents.AnyAsync(
            item => item.Id != id && item.Title == title && blockingStatuses.Contains(item.Status),
            cancellationToken);
        if (hasActiveDuplicate)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Інцидент із такою темою вже активний",
                detail: "Активний інцидент з такою самою темою вже існує.");
        }

        // Змінюються ЛИШЕ дозволені content fields; owner/status/severity цим маршрутом змінити неможливо.
        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new UpdatedIncidentResponse(
            incident.Id,
            incident.Title,
            incident.Description,
            incident.Severity.ToString(),
            incident.Status.ToString(),
            incident.OccurredAtUtc,
            incident.UpdatedAtUtc));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canDelete = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Delete);
        if (!canDelete.Succeeded)
        {
            return Results.Forbid();
        }

        db.Incidents.Remove(incident);
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            // Спроба privileged action над ресурсом, якого principal не бачить: у журнал, клієнту — звичайна 404.
            WriteDeniedAudit(logger, httpContext, "incident.triage", incident.Id);
            return IncidentNotFound();
        }

        var canTriage = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Triage);
        if (!canTriage.Succeeded)
        {
            WriteDeniedAudit(logger, httpContext, "incident.triage", incident.Id);
            return Results.Forbid();
        }

        // Допустимість переходу перевіряє сервер за ПОТОЧНИМ станом із БД; клієнт status не передає.
        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Перехід неможливий",
                detail: "Дозволений лише перехід New → Triaged.");
        }

        if (!IncidentAccessPolicy.TryGetUserId(httpContext.User, out var actorId))
        {
            return Results.Challenge();
        }

        var now = DateTimeOffset.UtcNow;
        var previousStatus = incident.Status;

        // Наступний статус встановлює СЕРВЕР.
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = actorId,
            OldStatus = previousStatus,
            NewStatus = IncidentStatus.Triaged,
            Note = "Первинну оцінку завершено аналітиком.",
            CreatedAtUtc = now
        });
        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new TriageIncidentResponse(incident.Id, incident.Status.ToString(), now));
    }

    // Audit event: structured fields, server-verified subject, server time і ТОЙ САМИЙ trace id,
    // що потрапляє в Problem Details відповіді. Немає cookie, password, token, body, stack trace.
    private static void WriteDeniedAudit(
        ILogger logger,
        HttpContext httpContext,
        string action,
        Guid resourceId)
    {
        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} "
            + "result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
            action,
            resourceId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);
    }
}