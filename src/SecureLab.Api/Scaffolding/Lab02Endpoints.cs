using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;
namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (
    string? q, string? sortBy, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
{
    // A-11: суб'єкт і його видимість - з principal; умова входить у запит ДО сортування і Take(50).
    if (!IncidentAccessPolicy.TryGetUserId(httpContext.User, out var userId))
    {
        return Results.Challenge();
    }

    var canReadAll = IncidentAccessPolicy.CanReadAll(httpContext.User);
    var pattern = "%" + EscapeLike(q ?? "") + "%";
    var found = db.Incidents.AsNoTracking()
        .Where(incident => canReadAll || incident.OwnerUserId == userId)
        .Where(incident =>
            EF.Functions.ILike(incident.Title, pattern, "\\")
            || EF.Functions.ILike(incident.Description, pattern, "\\"));

    IQueryable<Incident>? ordered = sortBy switch
    {
        null or "" or "createdAtUtc" => found
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .ThenBy(incident => incident.Id),
        "severity" => found
            .OrderBy(incident => incident.Severity == IncidentSeverity.Critical ? 0
                : incident.Severity == IncidentSeverity.High ? 1
                : incident.Severity == IncidentSeverity.Medium ? 2 : 3)
            .ThenBy(incident => incident.Id),
        "status" => found
            .OrderBy(incident => incident.Status == IncidentStatus.New ? 0
                : incident.Status == IncidentStatus.Triaged ? 1
                : incident.Status == IncidentStatus.InProgress ? 2
                : incident.Status == IncidentStatus.Resolved ? 3 : 4)
            .ThenBy(incident => incident.Id),
        _ => null
    };

    if (ordered is null)
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
        });

    var items = await ordered
        .Take(50)
        .Select(incident => new IncidentSearchItemResponse(
            incident.Id, incident.Title, incident.Description,
            incident.Severity.ToString(), incident.Status.ToString(), incident.CreatedAtUtc))
        .ToListAsync(ct);

    return Results.Ok(items);
}).RequireAuthorization();
       app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, HttpContext httpContext, CancellationToken ct) =>
       {
    var now = DateTimeOffset.UtcNow;
    var errors = new Dictionary<string, string[]>();

    if (string.IsNullOrWhiteSpace(request.Title))
        errors["title"] = ["Тема обов'язкова."];
    else if (request.Title.Length > 160)
        errors["title"] = ["Тема не довша за 160 символів."];

    if (string.IsNullOrWhiteSpace(request.Description))
        errors["description"] = ["Опис обов'язковий."];
    else if (request.Description.Length > 4000)
        errors["description"] = ["Опис не довший за 4000 символів."];

    var severityIsValid =
        Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
        && Enum.IsDefined(severity);
    if (!severityIsValid)
        errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

   if (request.OccurredAtUtc is null)
    errors["occurredAtUtc"] = ["Час настання події обов'язковий."];
else if (request.OccurredAtUtc > now.AddMinutes(5))
    errors["occurredAtUtc"] = ["Час настання події не може бути в майбутньому (допуск 5 хв)."];
else if (request.OccurredAtUtc < now.AddDays(-365))
    errors["occurredAtUtc"] = ["Час настання події не може бути старішим за 365 днів."];

    // 4. Нормалізація по одному разу.
    var title = request.Title?.Trim() ?? "";
    var description = request.Description?.Trim() ?? "";

    // 5. Cross-field (добрий рівень): High/Critical -> description >= 40 символів після Trim().
    if (severityIsValid && (severity is IncidentSeverity.High or IncidentSeverity.Critical)
        && !errors.ContainsKey("description") && description.Length < 40)
        errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];

    // 6. Якщо є будь-які помилки контракту — 400 до доступу до БД.
    if (errors.Count > 0)
        return Results.ValidationProblem(errors);

    var occurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();

    // 7. Предметний конфлікт (добрий рівень): той самий title (Trim(), з урахуванням регістру)
    //    серед New/Triaged/InProgress/Resolved (Closed не блокує).
    var blockingStatuses = new[]
    {
        IncidentStatus.New, IncidentStatus.Triaged,
        IncidentStatus.InProgress, IncidentStatus.Resolved
    };
    var hasActiveDuplicate = await db.Incidents.AnyAsync(
        item => item.Title == title && blockingStatuses.Contains(item.Status), ct);
    if (hasActiveDuplicate)
        return Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Інцидент із такою темою вже активний",
            detail: "Активний інцидент з такою самою темою вже існує.");

    // 8. Entity: server-managed поля встановлює лише сервер.
       var userIdClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!Guid.TryParse(userIdClaim, out var ownerUserId))
    {
        return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
    }
    var incident = new Incident
    {
        Id = Guid.NewGuid(),
       OwnerUserId = ownerUserId, 
        Title = title,
        Description = description,
        Severity = severity,
        Status = IncidentStatus.New,
        OccurredAtUtc = occurredAtUtc,
        CreatedAtUtc = now,
        UpdatedAtUtc = now
    };
    db.Incidents.Add(incident);
    await db.SaveChangesAsync(ct);

    // 9. Response DTO: лише поля зовнішнього контракту.
    var response = new CreatedIncidentResponse(
        incident.Id, incident.Title, incident.Description,
        incident.Severity.ToString(), incident.Status.ToString(),
        incident.OccurredAtUtc, incident.CreatedAtUtc);
     return Results.Created($"/api/incidents/{incident.Id}", response);
}).RequireAuthorization();
    }
    private static string EscapeLike(string value) =>
    value.Replace("\\", "\\\\").Replace("_", "\\_").Replace("%", "\\%");
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);

    public sealed record IncidentSearchItemResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset CreatedAtUtc);