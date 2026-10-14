using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        // Rate limiting на логін: партиціонування за IP-адресою клієнта, а не за іменем
        // користувача, щоб сам факт обмеження не видавав, існує акаунт чи ні.
        // 5 спроб на 15 секунд з одного IP — для лабораторної демонстрації відновлення вікна;
        // для production доцільне довше вікно (наприклад, 1 хвилина).
        builder.Services.AddRateLimiter(options =>
        {
            options.AddPolicy("login", httpContext => RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                               factory: _ => new FixedWindowRateLimiterOptions
                               {
                                   PermitLimit = 10,
                                   Window = TimeSpan.FromSeconds(10),
                                   QueueLimit = 0
                               }));
            options.OnRejected = (context, _) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return ValueTask.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users, ILogger<Program> logger) =>
        {
            const int maxUserNameLength = 256;
            const int maxEmailLength = 256;
            const int maxDisplayNameLength = 120;

            if (string.IsNullOrWhiteSpace(input.UserName) || input.UserName.Trim().Length > maxUserNameLength
                || string.IsNullOrWhiteSpace(input.Email) || input.Email.Trim().Length > maxEmailLength
                || string.IsNullOrWhiteSpace(input.DisplayName) || input.DisplayName.Trim().Length > maxDisplayNameLength
                || string.IsNullOrEmpty(input.Password))
            {
                return Results.BadRequest(new { message = "Registration failed" });
            }

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName.Trim(),
                Email = input.Email.Trim(),
                DisplayName = input.DisplayName.Trim()
            };
            var result = await users.CreateAsync(user, input.Password);
            if (!result.Succeeded)
            {
                logger.LogWarning("Registration failed for user {UserName}: {ErrorCodes}",
                    input.UserName, string.Join(",", result.Errors.Select(e => e.Code)));
                var isDuplicate = result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
                return isDuplicate
                    ? Results.Conflict(new { message = "Registration failed" })
                    : Results.BadRequest(new { message = "Registration failed" });
            }
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            logger.LogInformation("Registration succeeded for user {UserName}", user.UserName);
            return Results.Created("/api/me", new RegistrationResponse(user.Id, user.UserName!, user.DisplayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn, ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                logger.LogWarning("Login rejected: missing username or password");
                return Results.Unauthorized();
            }
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (result.Succeeded)
            {
                logger.LogInformation("Login succeeded for user {UserName}", input.UserName);
                return Results.NoContent();
            }
            logger.LogWarning("Login failed for user {UserName}", input.UserName);
            return Results.Unauthorized();
        }).RequireRateLimiting("login");
        app.MapPost("/api/auth/logout", async (HttpContext context, SignInManager<ApplicationUser> signIn, ILogger<Program> logger) =>
        {
            var userName = context.User.Identity?.Name;
            await signIn.SignOutAsync();
            logger.LogInformation("Logout for user {UserName}", userName);
            return Results.NoContent();
        });
        app.MapGet("/api/me", async (HttpContext context, UserManager<ApplicationUser> users) =>
        {
            var id = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = id is null ? null : await users.FindByIdAsync(id);
            return user is null ? Results.Unauthorized() : Results.Ok(new { user.Id, user.UserName, user.DisplayName });
        }).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);