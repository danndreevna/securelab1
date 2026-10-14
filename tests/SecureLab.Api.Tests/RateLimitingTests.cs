using System.Net;
using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public sealed class RateLimitingTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task ExceedingLoginAttempts_Returns429ThenRecoversAfterWindow()
    {
        using var client = factory.CreateClient();
        HttpResponseMessage? last = null;

        // Ліміт — 10 спроб на 10 секунд з одного IP; 11-й запит у цьому самому вікні має впасти в 429.
        for (var i = 0; i < 11; i++)
        {
            last?.Dispose();
            last = await client.PostAsJsonAsync("/api/auth/login",
                new { userName = "nosuchuser-rate-limit-probe", password = "WrongPassword1!" });
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, last!.StatusCode);
        last.Dispose();

        await Task.Delay(TimeSpan.FromSeconds(11));

        using var afterWindow = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "nosuchuser-rate-limit-probe", password = "WrongPassword1!" });

        // Після вікна обмеження зняте: відповідь — звичайний 401 (невідомий користувач), а не 429.
        Assert.Equal(HttpStatusCode.Unauthorized, afterWindow.StatusCode);
    }
}