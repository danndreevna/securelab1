using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace SecureLab.Api.Application.Incidents;

public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = "Read" };
    public static readonly OperationAuthorizationRequirement Update = new() { Name = "Update" };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = "Delete" };
    public static readonly OperationAuthorizationRequirement Triage = new() { Name = "Triage" };
}
