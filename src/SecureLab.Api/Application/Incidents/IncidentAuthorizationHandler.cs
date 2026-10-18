using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// Рішення = суб'єкт (хто) + дія (що) + ресурс (над чим) + контекст (статус).
public sealed class IncidentAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident incident)
    {
        var userIdValue = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Task.CompletedTask;
        }

        var isOwner = incident.OwnerUserId == userId;
        var isAnalyst = context.User.IsInRole(DbSeeder.AnalystRole);

        var allowed = false;
        if (requirement.Name == IncidentOperations.Read.Name)
        {
            allowed = isOwner || isAnalyst;
        }
        else if (requirement.Name == IncidentOperations.Update.Name)
        {
            allowed = isOwner;
        }
        else if (requirement.Name == IncidentOperations.Delete.Name)
        {
            allowed = isOwner && incident.Status == IncidentStatus.New;
        }
        else if (requirement.Name == IncidentOperations.Triage.Name)
        {
            allowed = isAnalyst;
        }

        if (allowed)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}