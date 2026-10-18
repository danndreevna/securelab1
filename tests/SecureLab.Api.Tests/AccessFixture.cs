using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// One factory per test class and one HttpClient (own cookie jar) per user.
// Logins happen once and lazily, so the login rate limit is never reached.
public sealed class AccessFixture : IDisposable
{
    private readonly Lazy<Task<HttpClient>> _anonymous;
    private readonly Lazy<Task<HttpClient>> _alice;
    private readonly Lazy<Task<HttpClient>> _bob;
    private readonly Lazy<Task<HttpClient>> _morgan;
    private readonly Lazy<Task<HttpClient>> _admin;
    private readonly ConcurrentBag<Guid> _created = new();

    public AccessFixture()
    {
        Factory = new SecureLabApiFactory();
        _anonymous = new(() => Task.FromResult(Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        })));
        _alice = new(() => Factory.LoginAsync("alice", SeedPassword()));
        _bob = new(() => Factory.LoginAsync("bob", SeedPassword()));
        _morgan = new(() => Factory.LoginAsync("morgan", SeedPassword()));
        _admin = new(() => Factory.LoginAsync("admin", SeedPassword()));
    }

    public SecureLabApiFactory Factory { get; }
    public Task<HttpClient> Anonymous => _anonymous.Value;
    public Task<HttpClient> Alice => _alice.Value;
    public Task<HttpClient> Bob => _bob.Value;
    public Task<HttpClient> Morgan => _morgan.Value;
    public Task<HttpClient> Admin => _admin.Value;

    public static string SeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A test that changes data works only with a resource it created itself (always status New).
    public async Task<Guid> CreateIncidentAsync(HttpClient client, string label)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"{label} {Guid.NewGuid():N}",
            description = "Lab 4 autotest record, removed after the test class.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();
        _created.Add(id);
        return id;
    }

    public void Dispose()
    {
        CleanupAsync().GetAwaiter().GetResult();
        Factory.Dispose();
    }

    private async Task CleanupAsync()
    {
        if (_created.IsEmpty)
        {
            return;
        }

        var ids = _created.ToArray();
        using var scope = Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incidents = await db.Incidents
            .Include(i => i.Comments)
            .Include(i => i.StatusHistory)
            .Where(i => ids.Contains(i.Id))
            .ToListAsync();
        foreach (var incident in incidents)
        {
            db.IncidentComments.RemoveRange(incident.Comments);
            db.IncidentStatusHistory.RemoveRange(incident.StatusHistory);
        }

        db.Incidents.RemoveRange(incidents);
        await db.SaveChangesAsync();
    }
}