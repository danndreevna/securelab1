using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentAuthorizationTests(AccessFixture fx) : IClassFixture<AccessFixture>
{
    private static readonly Guid BobSecondIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid AliceSecondIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000005");
    private static readonly Guid PublicCommentOnAliceId = Guid.Parse("30000000-0000-0000-0000-000000000001");
    private static readonly Guid CommentOnBobId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalCommentOnAliceId = Guid.Parse("30000000-0000-0000-0000-000000000003");

    private static string IncidentUrl(Guid id) => $"/api/incidents/{id}";
    private static string TriageUrl(Guid id) => $"/api/incidents/{id}/triage";
    private static string CommentUrl(Guid id) => $"/api/incident-comments/{id}";

    private static object ValidUpdate(string title) => new
    {
        title,
        description = "Lab 4 autotest: changed content.",
        severity = "Medium",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2)
    };

    private static async Task<JsonElement> ReadIncidentAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync(IncidentUrl(id));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static async Task<List<Guid>> SearchIdsAsync(HttpClient client, string query)
    {
        var rows = await client.GetFromJsonAsync<JsonElement>(
            $"/api/incidents/search?q={Uri.EscapeDataString(query)}");
        return rows.EnumerateArray().Select(row => row.GetProperty("id").GetGuid()).ToList();
    }

    // ---------- A-01 ----------
    [Theory]
    [InlineData("GET", "/api/incidents")]
    [InlineData("GET", "/api/incidents/search?q=usb")]
    [InlineData("GET", "/api/incidents/severity-summary")]
    [InlineData("GET", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("PUT", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("DELETE", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("POST", "/api/incidents/20000000-0000-0000-0000-000000000003/triage")]
    [InlineData("GET", "/api/incident-comments/30000000-0000-0000-0000-000000000001")]
    public async Task A01_Anonymous_ProtectedEndpoints_Return401NotRedirect(string method, string url)
    {
        var anonymous = await fx.Anonymous;
        using var request = new HttpRequestMessage(new HttpMethod(method), url);
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(ValidUpdate("anonymous attempt"));
        }

        using var response = await anonymous.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ---------- A-02 ----------
    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncidentWithoutInternalComments()
    {
        var alice = await fx.Alice;
        var me = await alice.GetFromJsonAsync<JsonElement>("/api/me");

        var incident = await ReadIncidentAsync(alice, DbSeeder.AliceIncidentId);

        Assert.Equal(
            me.GetProperty("displayName").GetString(),
            incident.GetProperty("ownerDisplayName").GetString());
        var commentIds = incident.GetProperty("comments").EnumerateArray()
            .Select(comment => comment.GetProperty("id").GetGuid()).ToList();
        Assert.Contains(PublicCommentOnAliceId, commentIds);
        Assert.DoesNotContain(InternalCommentOnAliceId, commentIds);
    }

    [Fact]
    public async Task A02_Update_AsOwner_ChangesOnlyAllowedContent()
    {
        var alice = await fx.Alice;
        var id = await fx.CreateIncidentAsync(alice, "A-02 update");
        var before = await ReadIncidentAsync(alice, id);

        using var response = await alice.PutAsJsonAsync(IncidentUrl(id), ValidUpdate("A-02 changed"));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var after = await ReadIncidentAsync(alice, id);
        Assert.Equal("A-02 changed", after.GetProperty("title").GetString());
        Assert.Equal("Medium", after.GetProperty("severity").GetString());
        Assert.Equal("New", after.GetProperty("status").GetString());
        Assert.Equal(
            before.GetProperty("ownerDisplayName").GetString(),
            after.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task A02_Delete_AsOwnerWhileNew_RemovesIncident()
    {
        var alice = await fx.Alice;
        var id = await fx.CreateIncidentAsync(alice, "A-02 delete");

        using var response = await alice.DeleteAsync(IncidentUrl(id));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        using var after = await alice.GetAsync(IncidentUrl(id));
        Assert.Equal(HttpStatusCode.NotFound, after.StatusCode);
    }

    // ---------- A-03 ----------
    [Fact]
    public async Task A03_Details_AsNonOwner_Returns403_WithoutOwnerData()
    {
        var alice = await fx.Alice;

        using var response = await alice.GetAsync(IncidentUrl(DbSeeder.BobIncidentId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("description", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ownerDisplayName", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("comments", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A03_Details_AsOtherReporter_Returns403_BothDirections()
    {
        var bob = await fx.Bob;

        using var response = await bob.GetAsync(IncidentUrl(DbSeeder.AliceIncidentId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A03_Details_ForUnknownId_Returns404()
    {
        var alice = await fx.Alice;

        using var response = await alice.GetAsync(IncidentUrl(Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsOtherUsersIncidents()
    {
        var morgan = await fx.Morgan;

        using var aliceIncident = await morgan.GetAsync(IncidentUrl(DbSeeder.AliceIncidentId));
        using var bobIncident = await morgan.GetAsync(IncidentUrl(DbSeeder.BobIncidentId));

        Assert.Equal(HttpStatusCode.OK, aliceIncident.StatusCode);
        Assert.Equal(HttpStatusCode.OK, bobIncident.StatusCode);
    }

    [Fact]
    public async Task A03_Details_AsAdministrator_Returns403_NoExtraIncidentRights()
    {
        var admin = await fx.Admin;

        using var response = await admin.GetAsync(IncidentUrl(DbSeeder.AliceIncidentId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ---------- A-04 ----------
    [Fact]
    public async Task A04_Update_AsNonOwner_Returns403_AndDoesNotChangeResource()
    {
        var alice = await fx.Alice;
        var bob = await fx.Bob;
        var before = await bob.GetStringAsync(IncidentUrl(DbSeeder.BobIncidentId));

        using var response = await alice.PutAsJsonAsync(
            IncidentUrl(DbSeeder.BobIncidentId), ValidUpdate("hijacked by alice"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await bob.GetStringAsync(IncidentUrl(DbSeeder.BobIncidentId));
        Assert.Equal(before, after);
    }

    [Fact]
    public async Task A04_Delete_AsNonOwner_Returns403_AndResourceStillExists()
    {
        var alice = await fx.Alice;
        var bob = await fx.Bob;
        var before = await bob.GetStringAsync(IncidentUrl(DbSeeder.BobIncidentId));

        using var response = await alice.DeleteAsync(IncidentUrl(DbSeeder.BobIncidentId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await bob.GetStringAsync(IncidentUrl(DbSeeder.BobIncidentId));
        Assert.Equal(before, after);
    }

    [Fact]
    public async Task A04_Delete_OwnIncidentThatIsNotNew_Returns403_AndResourceStillExists()
    {
        var alice = await fx.Alice;
        var before = await alice.GetStringAsync(IncidentUrl(DbSeeder.AliceIncidentId));

        using var response = await alice.DeleteAsync(IncidentUrl(DbSeeder.AliceIncidentId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await alice.GetStringAsync(IncidentUrl(DbSeeder.AliceIncidentId));
        Assert.Equal(before, after);
    }

    // ---------- A-05 ----------
    [Fact]
    public async Task A05_List_AsReporter_ReturnsOnlyOwnIncidents()
    {
        var alice = await fx.Alice;

        var list = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(list);
        Assert.Contains(list, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(list, item => item.Id == AliceSecondIncidentId);
        Assert.DoesNotContain(list, item => item.Id == DbSeeder.BobIncidentId);
        Assert.DoesNotContain(list, item => item.Id == BobSecondIncidentId);
    }

    [Fact]
    public async Task A05_List_AsAnalyst_ReturnsAllIncidents()
    {
        var morgan = await fx.Morgan;

        var list = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(list);
        Assert.Contains(list, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(list, item => item.Id == DbSeeder.BobIncidentId);
    }

    // ---------- A-06 ----------
    [Fact]
    public async Task A06_Triage_AsReporterOwner_Returns403_AndStatusStaysNew()
    {
        var alice = await fx.Alice;
        var id = await fx.CreateIncidentAsync(alice, "A-06 owner triage");

        using var response = await alice.PostAsync(TriageUrl(id), null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await ReadIncidentAsync(alice, id);
        Assert.Equal("New", after.GetProperty("status").GetString());
    }

    [Fact]
    public async Task A06_Triage_AsOtherReporter_Returns403_AndStatusStaysNew()
    {
        var alice = await fx.Alice;
        var bob = await fx.Bob;
        var id = await fx.CreateIncidentAsync(alice, "A-06 other reporter triage");

        using var response = await bob.PostAsync(TriageUrl(id), null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await ReadIncidentAsync(alice, id);
        Assert.Equal("New", after.GetProperty("status").GetString());
    }

    [Fact]
    public async Task A06_Triage_AsAdministrator_Returns403_AndStatusStaysNew()
    {
        var alice = await fx.Alice;
        var admin = await fx.Admin;
        var id = await fx.CreateIncidentAsync(alice, "A-06 admin triage");

        using var response = await admin.PostAsync(TriageUrl(id), null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await ReadIncidentAsync(alice, id);
        Assert.Equal("New", after.GetProperty("status").GetString());
    }

    // ---------- A-07 ----------
    [Fact]
    public async Task A07_Triage_AsAnalyst_MovesNewToTriaged_ThenRepeatReturns409()
    {
        var alice = await fx.Alice;
        var morgan = await fx.Morgan;
        var id = await fx.CreateIncidentAsync(alice, "A-07 triage");

        using var first = await morgan.PostAsync(TriageUrl(id), null);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var after = await ReadIncidentAsync(alice, id);
        Assert.Equal("Triaged", after.GetProperty("status").GetString());

        using var second = await morgan.PostAsync(TriageUrl(id), null);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task A07_Update_AsAnalyst_Returns403_RoleDoesNotGrantContentRights()
    {
        var alice = await fx.Alice;
        var morgan = await fx.Morgan;
        var id = await fx.CreateIncidentAsync(alice, "A-07 analyst update");
        var before = await alice.GetStringAsync(IncidentUrl(id));

        using var update = await morgan.PutAsJsonAsync(IncidentUrl(id), ValidUpdate("changed by analyst"));
        using var delete = await morgan.DeleteAsync(IncidentUrl(id));

        Assert.Equal(HttpStatusCode.Forbidden, update.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        var after = await alice.GetStringAsync(IncidentUrl(id));
        Assert.Equal(before, after);
    }

    // ---------- A-08a ----------
    [Fact]
    public async Task A08a_Update_WithForgedOwnerRoleAndStatus_IgnoresUnknownFields()
    {
        var alice = await fx.Alice;
        var id = await fx.CreateIncidentAsync(alice, "A-08a forged update");

        using var response = await alice.PutAsJsonAsync(IncidentUrl(id), new
        {
            title = "A-08a changed",
            description = "Lab 4 autotest: changed content.",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2),
            ownerUserId = DbSeeder.BobId,
            role = "Administrator",
            status = "Resolved",
            isTransitionAllowed = true
        });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var after = await ReadIncidentAsync(alice, id);
        Assert.Equal("A-08a changed", after.GetProperty("title").GetString());

        using var scope = fx.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var stored = await db.Incidents.FindAsync(id);
        Assert.NotNull(stored);
        Assert.Equal(DbSeeder.AliceId, stored!.OwnerUserId);
        Assert.Equal(IncidentStatus.New, stored.Status);
    }

    // ---------- A-09 ----------
    [Fact]
    public async Task A09_DeniedTriage_WritesAuditEventWithSameTraceId_AndNoSecrets()
    {
        var alice = await fx.Alice;
        var id = await fx.CreateIncidentAsync(alice, "A-09 audit");

        using var response = await alice.PostAsync(TriageUrl(id), null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        var traceId = problem.GetProperty("traceId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(traceId));

        var audit = Assert.Single(
            fx.Factory.Logs.Messages,
            message => message.Contains($"resource=incident/{id}", StringComparison.Ordinal));
        Assert.Contains($"subject={DbSeeder.AliceId}", audit);
        Assert.Contains("action=incident.triage", audit);
        Assert.Contains("result=denied", audit);
        Assert.Contains("at=", audit);
        Assert.Contains($"trace={traceId}", audit);
        Assert.DoesNotContain("password", audit, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cookie", audit, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(AccessFixture.SeedPassword(), audit, StringComparison.Ordinal);
    }

    // ---------- A-11 ----------
    [Fact]
    public async Task A11_Search_AsReporter_ReturnsOnlyOwnIncidents()
    {
        var alice = await fx.Alice;
        var morgan = await fx.Morgan;

        var aliceOwn = await SearchIdsAsync(alice, "USB");
        var aliceForeign = await SearchIdsAsync(alice, "Brien");
        var analystForeign = await SearchIdsAsync(morgan, "Brien");

        Assert.Contains(AliceSecondIncidentId, aliceOwn);
        Assert.DoesNotContain(BobSecondIncidentId, aliceForeign);
        Assert.Contains(BobSecondIncidentId, analystForeign);
    }

    [Fact]
    public async Task A11_SeveritySummary_AsReporter_CountsOnlyOwnIncidents()
    {
        var alice = await fx.Alice;
        var morgan = await fx.Morgan;

        var aliceList = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        var aliceSummary = await alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");
        var morganSummary = await morgan.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.NotNull(aliceList);
        Assert.NotNull(aliceSummary);
        Assert.NotNull(morganSummary);
        Assert.Equal(aliceList!.Count, aliceSummary!.Sum(row => row.Count));
        Assert.True(morganSummary!.Sum(row => row.Count) > aliceSummary.Sum(row => row.Count));
    }

    // ---------- A-12 ----------
    [Fact]
    public async Task A12_Comment_OfOtherUsersIncident_Returns403_WithoutCommentData()
    {
        var alice = await fx.Alice;

        using var response = await alice.GetAsync(CommentUrl(CommentOnBobId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("authorDisplayName", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A12_InternalComment_AsReporterOwnerOfIncident_Returns403()
    {
        var alice = await fx.Alice;

        using var response = await alice.GetAsync(CommentUrl(InternalCommentOnAliceId));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("authorDisplayName", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A12_PublicComment_AsOwnerAndInternalComment_AsAnalyst_Return200()
    {
        var alice = await fx.Alice;
        var morgan = await fx.Morgan;

        using var publicForOwner = await alice.GetAsync(CommentUrl(PublicCommentOnAliceId));
        using var internalForAnalyst = await morgan.GetAsync(CommentUrl(InternalCommentOnAliceId));

        Assert.Equal(HttpStatusCode.OK, publicForOwner.StatusCode);
        Assert.Equal(HttpStatusCode.OK, internalForAnalyst.StatusCode);
    }

    [Fact]
    public async Task A12_Comment_ForUnknownId_Returns404()
    {
        var alice = await fx.Alice;

        using var response = await alice.GetAsync(CommentUrl(Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}