namespace SecureLab.Api.Presentation.Contracts;

// Звичайний update приймає лише content fields. Немає ні Status, ні OwnerUserId, ні Role:
// клієнт фізично не може їх передати. Зайві поля в JSON мовчки ігноруються (контракт A-08a).
public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description);