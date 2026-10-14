using System.Net;
using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public sealed class SessionRevocationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task RevokeAllSessions_InvalidatesExistingCookieImmediately()
    {
        using var client = await factory.LoginAsync("alice", RequireSeedPassword());

        using var meBefore = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, meBefore.StatusCode);

        using var revoke = await client.PostAsync("/api/auth/sessions/revoke-all", null);
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        // Той самий cookie (ніхто його не видаляв, явного logout не було) більше не минає
        // перевірку: security stamp на сервері змінився, а ValidationInterval=Zero перевіряє
        // це на кожен запит, а не раз на 30 хвилин.
        using var meAfter = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, meAfter.StatusCode);
    }

    [Fact]
    public async Task RevokeAllSessions_AnonymousCaller_Returns401()
    {
        using var client = factory.CreateClient();

        using var response = await client.PostAsync("/api/auth/sessions/revoke-all", null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}