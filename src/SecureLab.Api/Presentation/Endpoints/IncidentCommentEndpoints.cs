using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentCommentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentCommentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // PoC (vulnerable): коментар шукається лише за власним id, без перевірки parent incident.
        endpoints.MapGet("/api/incident-comments/{id:guid}", async (
                Guid id,
                SecureLabDbContext db,
                CancellationToken cancellationToken) =>
            {
                var comment = await db.IncidentComments
                    .AsNoTracking()
                    .Where(item => item.Id == id)
                    .Select(item => new IncidentCommentResponse(
                        item.Id,
                        item.Author.DisplayName,
                        item.Text,
                        item.CreatedAtUtc))
                    .SingleOrDefaultAsync(cancellationToken);
                return comment is null ? Results.NotFound() : Results.Ok(comment);
            })
            .WithName("GetIncidentComment")
            .WithTags("Incidents")
            .RequireAuthorization();

        return endpoints;
    }
}