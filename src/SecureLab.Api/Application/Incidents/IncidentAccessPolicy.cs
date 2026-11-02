using System.Security.Claims;
using SecureLab.Api.Data;

namespace SecureLab.Api.Application.Incidents;

/// <summary>
/// Єдине місце, де з principal читаються ідентифікатор і «широка» видимість.
/// Ним користуються і handler, і query scoping (list/search/summary), тож правило не розходиться.
/// </summary>
public static class IncidentAccessPolicy
{
    public static bool TryGetUserId(ClaimsPrincipal user, out Guid userId) =>
        Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out userId);

    // Лише Analyst читає чужі інциденти. Administrator прямого права не має (матриця доступу).
    public static bool CanReadAll(ClaimsPrincipal user) =>
        user.IsInRole(DbSeeder.AnalystRole);
}