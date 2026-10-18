using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .WithTags("Incidents")
            .RequireAuthorization()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static IResult NotFoundProblem(string title) =>
        Results.Problem(title: title, statusCode: StatusCodes.Status404NotFound);

    private static string TraceId(HttpContext httpContext) =>
        Activity.Current?.Id ?? httpContext.TraceIdentifier;

    // traceId у відповіді клієнту збігається з trace у audit-події.
    private static IResult ForbiddenProblem(HttpContext httpContext) =>
        Results.Problem(
            title: "Доступ заборонено",
            statusCode: StatusCodes.Status403Forbidden,
            extensions: new Dictionary<string, object?> { ["traceId"] = TraceId(httpContext) });

    // Audit event: суб'єкт, дія, ресурс, результат, час сервера, trace id.
    // Cookie, пароль, токени та тіло запиту сюди не потрапляють.
    private static void AuditDenied(
        ILogger logger,
        HttpContext httpContext,
        IncidentViewer viewer,
        string action,
        string resourceType,
        Guid resourceId)
    {
        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceType}/{ResourceId} result=denied at={OccurredAtUtc:o} trace={TraceId}",
            viewer.UserId,
            action,
            resourceType,
            resourceId,
            DateTimeOffset.UtcNow,
            TraceId(httpContext));
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, viewer, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        IAuthorizationService authorization,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        var incident = await queries.FindAsync(id, track: false, cancellationToken);
        if (incident is null)
        {
            return NotFoundProblem("Інцидент не знайдено");
        }

        var decision = await authorization.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read);
        if (!decision.Succeeded)
        {
            AuditDenied(logger, httpContext, viewer, "incident.read", "incident", id);
            return ForbiddenProblem(httpContext);
        }

        var details = await queries.GetDetailsAsync(id, viewer.IsAnalyst, cancellationToken);
        return details is null
            ? NotFoundProblem("Інцидент не знайдено")
            : Results.Ok(details);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        var allowedStatuses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "New",
            "Triaged",
            "Resolved"
        };

        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!allowedStatuses.Contains(status))
            {
                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["status"] = [$"Unknown status filter '{status}'. Supported values: New, Triaged, Resolved."]
                    },
                    title: "One or more validation errors occurred.",
                    statusCode: StatusCodes.Status400BadRequest);
            }
        }

        var summary = await queries.GetSeveritySummaryAsync(
            status,
            httpContext.TraceIdentifier,
            viewer,
            cancellationToken);

        return Results.Ok(summary);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        IAuthorizationService authorization,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        var incident = await queries.FindAsync(id, track: true, cancellationToken);
        if (incident is null)
        {
            return NotFoundProblem("Інцидент не знайдено");
        }

        // Спочатку право на ресурс, і лише потім валідація та зміна.
        var decision = await authorization.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Update);
        if (!decision.Succeeded)
        {
            AuditDenied(logger, httpContext, viewer, "incident.update", "incident", id);
            return ForbiddenProblem(httpContext);
        }

        var now = DateTimeOffset.UtcNow;
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
        {
            errors["title"] = ["Поле title є обов'язковим."];
        }
        else if (request.Title.Trim().Length > 160)
        {
            errors["title"] = ["Довжина title не може перевищувати 160 символів."];
        }

        if (string.IsNullOrWhiteSpace(request.Description))
        {
            errors["description"] = ["Поле description є обов'язковим."];
        }
        else if (request.Description.Trim().Length > 4000)
        {
            errors["description"] = ["Довжина description не може перевищувати 4000 символів."];
        }

        IncidentSeverity severity = default;
        if (string.IsNullOrWhiteSpace(request.Severity))
        {
            errors["severity"] = ["Поле severity є обов'язковим."];
        }
        else if (!Enum.TryParse(request.Severity, true, out severity) || !Enum.IsDefined(severity))
        {
            errors["severity"] = ["Вказано неприпустиме значення severity."];
        }

        if (!request.OccurredAtUtc.HasValue)
        {
            errors["occurredAtUtc"] = ["Поле occurredAtUtc є обов'язковим."];
        }
        else if (request.OccurredAtUtc.Value > now.AddMinutes(5))
        {
            errors["occurredAtUtc"] = ["Час occurredAtUtc не може випереджати поточний час сервера більш ніж на 5 хвилин."];
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors, title: "Validation failed");
        }

        // Змінюються лише дозволені поля змісту. Owner, role і status тут недосяжні.
        incident.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        incident.Severity = severity;
        incident.OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();
        incident.UpdatedAtUtc = now;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        IAuthorizationService authorization,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        var incident = await dbContext.Incidents
            .Include(i => i.Comments)
            .Include(i => i.StatusHistory)
            .SingleOrDefaultAsync(i => i.Id == id, cancellationToken);
        if (incident is null)
        {
            return NotFoundProblem("Інцидент не знайдено");
        }

        var decision = await authorization.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Delete);
        if (!decision.Succeeded)
        {
            AuditDenied(logger, httpContext, viewer, "incident.delete", "incident", id);
            return ForbiddenProblem(httpContext);
        }

        dbContext.IncidentComments.RemoveRange(incident.Comments);
        dbContext.IncidentStatusHistory.RemoveRange(incident.StatusHistory);
        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        IAuthorizationService authorization,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        var incident = await queries.FindAsync(id, track: true, cancellationToken);
        if (incident is null)
        {
            return NotFoundProblem("Інцидент не знайдено");
        }

        var decision = await authorization.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Triage);
        if (!decision.Succeeded)
        {
            AuditDenied(logger, httpContext, viewer, "incident.triage", "incident", id);
            return ForbiddenProblem(httpContext);
        }

        // Перехід фіксований: лише New -> Triaged. Новий статус задає сервер, не клієнт.
        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Недопустимий перехід статусу",
                detail: "Перевести в Triaged можна лише інцидент зі статусом New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        var now = DateTimeOffset.UtcNow;
        var analyst = await dbContext.Users.SingleAsync(user => user.Id == viewer.UserId, cancellationToken);

        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            Incident = incident,
            ChangedByUser = analyst,
            OldStatus = IncidentStatus.New,
            NewStatus = IncidentStatus.Triaged,
            Note = "Первинну оцінку виконано.",
            CreatedAtUtc = now
        });

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.Ok(new { id = incident.Id, status = incident.Status.ToString() });
    }

    // Непрямий доступ: коментар перевіряється через батьківський інцидент
    // і додатково через ознаку IsInternal.
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        IAuthorizationService authorization,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        if (IncidentViewer.From(httpContext.User) is not { } viewer)
        {
            return Results.Unauthorized();
        }

        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Include(c => c.Incident)
            .Include(c => c.Author)
            .SingleOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (comment is null)
        {
            return NotFoundProblem("Коментар не знайдено");
        }

        var parent = await authorization.AuthorizeAsync(httpContext.User, comment.Incident, IncidentOperations.Read);
        if (!parent.Succeeded || (comment.IsInternal && !viewer.IsAnalyst))
        {
            AuditDenied(logger, httpContext, viewer, "incident-comment.read", "incident-comment", id);
            return ForbiddenProblem(httpContext);
        }

        return Results.Ok(new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc));
    }
}