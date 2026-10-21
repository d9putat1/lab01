namespace SecureLab.Api.Presentation.Contracts;

// УВАГА: навмисно вразливий контракт для PoC (vulnerable commit).
// Звичайний update приймає захищені поля: Severity, Status і OwnerUserId.
// У fixed-стані вони зникнуть.
public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    string? Status,
    Guid? OwnerUserId);