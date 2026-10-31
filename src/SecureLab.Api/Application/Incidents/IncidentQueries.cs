using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public static class IncidentReadScope
{   
    public static Expression<Func<Incident, bool>> BySubject(Guid userId, bool canReadAll) =>
        incident => canReadAll || incident.OwnerUserId == userId;
}

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        Guid userId,
        bool canReadAll,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents
            .AsNoTracking()
            .Where(IncidentReadScope.BySubject(userId, canReadAll));

        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<Incident?> FindForDecisionAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.Incidents
            .AsNoTracking()
            .SingleOrDefaultAsync(incident => incident.Id == id, cancellationToken);

    public Task<IncidentComment?> FindCommentForDecisionAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.IncidentComments
            .AsNoTracking()
            .Include(comment => comment.Incident)
            .Include(comment => comment.Author)
            .SingleOrDefaultAsync(comment => comment.Id == id, cancellationToken);

    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        bool includeInternalComments,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternalComments || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    // A-11 (Call site 2): спільний Expression-helper стоїть ДО фільтра status і ДО GroupBy.
    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentStatus? status,
        Guid userId,
        bool canReadAll,
        string traceId,
        CancellationToken cancellationToken)
    {
        var query = dbContext.Incidents
            .AsNoTracking()
            .Where(IncidentReadScope.BySubject(userId, canReadAll));

        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }
logger.LogInformation("SQL Proof (A-11 Summary):\n{Sql}", query.ToQueryString());
        var counts = await query
            .GroupBy(incident => incident.Severity)
            .Select(group => new { Severity = group.Key, Count = group.Count() })
            .ToListAsync(cancellationToken);

        var lookup = counts.ToDictionary(item => item.Severity, item => item.Count);

        var orderedSeverities = new[]
        {
            IncidentSeverity.Critical,
            IncidentSeverity.High,
            IncidentSeverity.Medium,
            IncidentSeverity.Low,
        };

        var result = orderedSeverities
            .Select(severity => new IncidentSeveritySummaryResponse(
                severity.ToString(),
                lookup.GetValueOrDefault(severity, 0)))
            .ToList();

        logger.LogInformation(
            "Severity summary computed: {GroupCount} groups, statusFilter={StatusFilter}, traceId={TraceId}",
            result.Count,
            status?.ToString() ?? "none",
            traceId);

        return result;
    }
}