using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthorizationRegressionTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task A01_AnonymousCreate_Returns401NotRedirect()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"A-01 anonymous probe {Guid.NewGuid():N}",
            description = "Anonymous create attempt, must never reach the database.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A02_LoginThenMe_ReturnsAuthenticatedUser()
    {
        using var client = await factory.LoginAsync("alice", RequireSeedPassword());

        var profile = await client.GetFromJsonAsync<JsonElement>("/api/me");

        Assert.Equal(DbSeeder.AliceId.ToString(), profile.GetProperty("id").GetString(), StringComparer.OrdinalIgnoreCase);
        Assert.Equal("alice", profile.GetProperty("userName").GetString());
    }

    [Fact]
    public async Task A03_ValidCookieWithForgedHeader_MeStaysWithActualPrincipal()
    {
        using var client = await factory.LoginAsync("bob", RequireSeedPassword());
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.AliceId.ToString());

        using var response = await client.SendAsync(request);
        var profile = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.BobId.ToString(), profile.GetProperty("id").GetString(), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A04_AuthenticatedCreate_OwnerComesFromPrincipal()
    {
        using var client = await factory.LoginAsync("bob", RequireSeedPassword());

        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"A-04 owner from principal {Guid.NewGuid():N}",
            description = "Authenticated create, request DTO has no owner field at all.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.FindAsync(id);

        Assert.NotNull(incident);
        Assert.Equal(DbSeeder.BobId, incident!.OwnerUserId);
    }

    [Fact]
    public async Task A05_ForgedOwnerUserIdInBody_IsIgnored()
    {
        using var client = await factory.LoginAsync("bob", RequireSeedPassword());

        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"A-05 forged owner {Guid.NewGuid():N}",
            description = "JSON body claims ownerUserId of Alice while authenticated as Bob.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = DbSeeder.AliceId
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.FindAsync(id);

        Assert.NotNull(incident);
        Assert.Equal(DbSeeder.BobId, incident!.OwnerUserId);
    }

    [Fact]
    public async Task A06_Logout_ThenMeReturns401()
    {
        using var client = await factory.LoginAsync("alice", RequireSeedPassword());
        using var meBefore = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, meBefore.StatusCode);

        using var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var meAfter = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, meAfter.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_ReturnIdenticalResult()
    {
        using var client = factory.CreateClient();

        using var unknownUser = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = $"nosuchuser-{Guid.NewGuid():N}", password = "WhateverPassword1!" });
        using var wrongPassword = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "DefinitelyWrong1!" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknownUser.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(unknownUser.Content.Headers.ContentType?.MediaType, wrongPassword.Content.Headers.ContentType?.MediaType);

        var unknownJson = JsonDocument.Parse(await unknownUser.Content.ReadAsStringAsync()).RootElement;
        var wrongJson = JsonDocument.Parse(await wrongPassword.Content.ReadAsStringAsync()).RootElement;

        // traceId різний для кожного запиту за задумом (ASP.NET) — не доказ, не порівнюємо.
        Assert.Equal(unknownJson.GetProperty("status").GetInt32(), wrongJson.GetProperty("status").GetInt32());
        Assert.Equal(unknownJson.GetProperty("title").GetString(), wrongJson.GetProperty("title").GetString());
        Assert.Equal(unknownJson.GetProperty("type").GetString(), wrongJson.GetProperty("type").GetString());
    }
}