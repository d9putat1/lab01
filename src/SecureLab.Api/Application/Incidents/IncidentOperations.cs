using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace SecureLab.Api.Application.Incidents;

/// <summary>Операції над Incident, для яких handler ухвалює рішення.</summary>
public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read =
        new() { Name = nameof(Read) };

    public static readonly OperationAuthorizationRequirement ReadInternalComments =
        new() { Name = nameof(ReadInternalComments) };

    public static readonly OperationAuthorizationRequirement Update =
        new() { Name = nameof(Update) };

    public static readonly OperationAuthorizationRequirement Delete =
        new() { Name = nameof(Delete) };

    public static readonly OperationAuthorizationRequirement Triage =
        new() { Name = nameof(Triage) };
}