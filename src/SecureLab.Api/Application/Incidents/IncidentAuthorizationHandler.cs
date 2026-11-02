using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident incident)
    {
        // Три входи рішення: principal, конкретний ресурс, операція (+ контекст: статус ресурсу).
        var isOwner = IncidentAccessPolicy.TryGetUserId(context.User, out var userId)
            && incident.OwnerUserId == userId;
        var isAnalyst = context.User.IsInRole(DbSeeder.AnalystRole);

        var allowed = requirement.Name switch
        {
            nameof(IncidentOperations.Read) =>
                isOwner || IncidentAccessPolicy.CanReadAll(context.User),

            nameof(IncidentOperations.ReadInternalComments) =>
                isAnalyst,

            nameof(IncidentOperations.Update) =>
                isOwner,

            nameof(IncidentOperations.Delete) =>
                isOwner && incident.Status == IncidentStatus.New,

            // Роль визначає право на privileged transition; допустимість поточного статусу
            // перевіряє endpoint (409), а наступний статус встановлює сервер.
            nameof(IncidentOperations.Triage) =>
                isAnalyst,

            _ => false
        };

        if (allowed)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}