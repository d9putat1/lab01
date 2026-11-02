using Microsoft.AspNetCore.Authorization;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentCommentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentCommentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .WithTags("Incidents")
            .RequireAuthorization()
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static IResult CommentNotFound() => Results.Problem(
        title: "Коментар не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        // Child завантажується разом із parent; рішення ухвалюється для БАТЬКІВСЬКОГО інциденту.
        var comment = await queries.FindCommentForDecisionAsync(id, cancellationToken);
        if (comment is null)
        {
            return CommentNotFound();
        }

        var canReadParent = await authorizationService.AuthorizeAsync(
            httpContext.User, comment.Incident, IncidentOperations.Read);
        if (!canReadParent.Succeeded)
        {
            return CommentNotFound();
        }

        if (comment.IsInternal)
        {
            var canReadInternal = await authorizationService.AuthorizeAsync(
                httpContext.User, comment.Incident, IncidentOperations.ReadInternalComments);
            if (!canReadInternal.Succeeded)
            {
                // Internal коментар для Reporter (навіть власника інциденту) не існує.
                return CommentNotFound();
            }
        }

        return Results.Ok(new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc));
    }
}