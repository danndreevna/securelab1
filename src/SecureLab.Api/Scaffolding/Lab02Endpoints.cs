using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // Allowlist для sortBy: будь-яке значення поза списком — 400, а не підстановка в ORDER BY.
            string[] allowedSortBy = ["createdAtUtc", "severity", "status"];
            if (!string.IsNullOrEmpty(sortBy) && !allowedSortBy.Contains(sortBy))
            {
                var sortErrors = new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                };
                return Results.ValidationProblem(sortErrors, title: "Validation failed");
            }

            // Екранування q: спецсимволи LIKE/ILIKE (\, %, _) нейтралізуються до того,
            // як значення потрапить у патерн, інакше клієнт керує структурою запиту.
            var safeQ = q ?? "";
            var escapedQ = safeQ.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
            var pattern = $"%{escapedQ}%";

            var query = db.Incidents.AsNoTracking().Where(i =>
                EF.Functions.ILike(i.Title, pattern, "\\") ||
                EF.Functions.ILike(i.Description, pattern, "\\"));

            query = sortBy switch
            {
                "severity" => query.OrderBy(i => i.Severity).ThenBy(i => i.Id),
                "status" => query.OrderBy(i => i.Status).ThenBy(i => i.Id),
                _ => query.OrderByDescending(i => i.CreatedAtUtc).ThenBy(i => i.Id)
            };

            var rows = await query.Take(50).ToListAsync(ct);

            return Results.Ok(rows.Select(row => new
            {
                row.Id,
                row.Title,
                row.Description,
                Severity = row.Severity.ToString(),
                Status = row.Status.ToString(),
                row.CreatedAtUtc
            }));
        });

        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            if (string.IsNullOrWhiteSpace(request.Title))
            {
                errors["title"] = ["Поле title є обов'язковим."];
            }
            else if (request.Title.Length > 160)
            {
                errors["title"] = ["Довжина title не може перевищувати 160 символів."];
            }

            if (string.IsNullOrWhiteSpace(request.Description))
            {
                errors["description"] = ["Поле description є обов'язковим."];
            }
            else if (request.Description.Length > 4000)
            {
                errors["description"] = ["Довжина description не може перевищувати 4000 символів."];
            }

            var parsedSeverity = default(IncidentSeverity);
            if (string.IsNullOrWhiteSpace(request.Severity))
            {
                errors["severity"] = ["Поле severity є обов'язковим."];
            }
            else if (!Enum.TryParse(request.Severity, true, out parsedSeverity)
                     || !Enum.IsDefined(parsedSeverity))
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
            else if (request.OccurredAtUtc.Value < now.AddDays(-365))
            {
                // T-10 (відмінний рівень, власне предметне правило): інцидент не може бути старішим за рік.
                errors["occurredAtUtc"] = ["Час occurredAtUtc не може бути давнішим ніж за 365 днів від поточного часу."];
            }

            var normalizedTitle = request.Title?.Trim() ?? "";
            var normalizedDescription = request.Description?.Trim() ?? "";

            // T-09 (добрий рівень): для High/Critical опис після Trim() має бути не коротшим за 40 символів.
            if (!errors.ContainsKey("severity") && !errors.ContainsKey("description")
                && (parsedSeverity == IncidentSeverity.High || parsedSeverity == IncidentSeverity.Critical)
                && normalizedDescription.Length < 40)
            {
                errors["description"] = ["Для рівнів High та Critical опис після Trim() має містити щонайменше 40 символів."];
            }

            if (errors.Count > 0)
            {
                return Results.ValidationProblem(errors, title: "Validation failed");
            }

            // T-03 (добрий рівень): предметний конфлікт за нормалізованим title серед активних статусів.
            var activeStatuses = new[]
            {
                IncidentStatus.New, IncidentStatus.Triaged, IncidentStatus.InProgress, IncidentStatus.Resolved
            };
            var hasConflict = await db.Incidents
                .AnyAsync(i => i.Title == normalizedTitle && activeStatuses.Contains(i.Status), ct);
            if (hasConflict)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Conflict",
                    detail: "Активний інцидент із таким заголовком уже існує.");
            }

            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = DbSeeder.AliceId,
                Title = normalizedTitle,
                Description = normalizedDescription,
                Severity = parsedSeverity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            var response = new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc);

            return Results.Created($"/api/incidents/{incident.Id}", response);
        });
    }
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);