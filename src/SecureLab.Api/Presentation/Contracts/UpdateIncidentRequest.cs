namespace SecureLab.Api.Presentation.Contracts;

// Свідомо немає OwnerUserId, Role, Status: клієнт не може їх задати.
public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);