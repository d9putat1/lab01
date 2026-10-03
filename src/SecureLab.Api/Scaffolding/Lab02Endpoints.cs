using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var order = sortBy switch
            {
                null or "" or "createdAtUtc" => "created_at_utc DESC",
                "severity" => "severity", "status" => "status", _ => sortBy
            };
            var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "")
                + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";
            var rows = await db.Incidents.FromSqlRaw(sql).AsNoTracking().ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id, row.Title, row.Description,
                Severity = row.Severity.ToString(), Status = row.Status.ToString(), row.CreatedAtUtc
            }));
        });
       app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow;
    var errors = new Dictionary<string, string[]>();

    // 1. Required і довжини — на вхідному значенні, до Trim().
    if (string.IsNullOrWhiteSpace(request.Title))
        errors["title"] = ["Тема обов'язкова."];
    else if (request.Title.Length > 160)
        errors["title"] = ["Тема не довша за 160 символів."];

    if (string.IsNullOrWhiteSpace(request.Description))
        errors["description"] = ["Опис обов'язковий."];
    else if (request.Description.Length > 4000)
        errors["description"] = ["Опис не довший за 4000 символів."];

    // 2. Severity: TryParse І IsDefined.
    var severityIsValid =
        Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
        && Enum.IsDefined(severity);
    if (!severityIsValid)
        errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

    // 3. occurredAtUtc: обов'язковий, не більш ніж на 5 хв у майбутньому.
    if (request.OccurredAtUtc is null)
        errors["occurredAtUtc"] = ["Час настання події обов'язковий."];
    else if (request.OccurredAtUtc > now.AddMinutes(5))
        errors["occurredAtUtc"] = ["Час настання події не може бути в майбутньому (допуск 5 хв)."];

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
    var incident = new Incident
    {
        Id = Guid.NewGuid(),
        OwnerUserId = DbSeeder.AliceId,
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
});
    }
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