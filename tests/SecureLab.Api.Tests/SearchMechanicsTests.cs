using System.Net;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(AccessFixture fx) : IClassFixture<AccessFixture>
{
    [Fact]
    public async Task Search_ReturnsJson()
    {
        var alice = await fx.Alice;

        using var response = await alice.GetAsync("/api/incidents/search?q=USB");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}