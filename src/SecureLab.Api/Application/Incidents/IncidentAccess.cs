using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// Суб'єкт береться лише з перевіреного принципала (cookie), а не з запиту.
public readonly record struct IncidentViewer(Guid UserId, bool IsAnalyst)
{
    public static IncidentViewer? From(ClaimsPrincipal user)
    {
        var value = user.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(value, out var id)
            ? new IncidentViewer(id, user.IsInRole(DbSeeder.AnalystRole))
            : null;
    }
}

public static class IncidentScope
{
    // Query scoping: Analyst бачить усе, інші лише власні інциденти.
    public static IQueryable<Incident> VisibleTo(this IQueryable<Incident> incidents, IncidentViewer viewer)
    {
        if (viewer.IsAnalyst)
        {
            return incidents;
        }

        var userId = viewer.UserId;
        return incidents.Where(incident => incident.OwnerUserId == userId);
    }
}