using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SentinelFlow.Tests;

public sealed class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public ApiTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ServesDashboardWithDefensiveHeaders()
    {
        var response = await _client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public async Task SummaryExposesOperationalSecurityMetrics()
    {
        var payload = await GetJson("/api/summary");
        Assert.Equal(3, payload.RootElement.GetProperty("projects").GetInt32());
        Assert.True(payload.RootElement.GetProperty("openFindings").GetInt32() > 0);
        Assert.True(payload.RootElement.GetProperty("coverage").GetInt32() > 0);
    }

    [Fact]
    public async Task RunDetailReturnsPolicyDecisionAndFindings()
    {
        var payload = await GetJson("/api/runs/run-1042");
        Assert.Equal("run-1042", payload.RootElement.GetProperty("run").GetProperty("id").GetString());
        Assert.Equal("blocked", payload.RootElement.GetProperty("run").GetProperty("decision").GetProperty("decision").GetString());
        Assert.True(payload.RootElement.GetProperty("findings").GetArrayLength() > 0);
    }

    [Fact]
    public async Task ManagerRoleCannotUpdateFinding()
    {
        var request = new HttpRequestMessage(HttpMethod.Patch, "/api/findings/finding-sqli")
        {
            Content = JsonContent.Create(new { status = "resolved" })
        };
        request.Headers.Add("X-Demo-Role", "manager");
        var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task DeveloperRoleCanTriageFinding()
    {
        var request = new HttpRequestMessage(HttpMethod.Patch, "/api/findings/finding-sqli")
        {
            Content = JsonContent.Create(new { status = "in_progress", owner = "Payments remediation squad" })
        };
        request.Headers.Add("X-Demo-Role", "developer");
        var response = await _client.SendAsync(request);
        var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Payments remediation squad", payload.RootElement.GetProperty("finding").GetProperty("owner").GetString());
    }

    [Fact]
    public async Task OnlySecurityRoleCanChangePolicyThresholds()
    {
        var denied = new HttpRequestMessage(HttpMethod.Put, "/api/policies/policy-default") { Content = JsonContent.Create(new { thresholds = new { high = 5 } }) };
        denied.Headers.Add("X-Demo-Role", "developer");
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(denied)).StatusCode);

        var allowed = new HttpRequestMessage(HttpMethod.Put, "/api/policies/policy-default") { Content = JsonContent.Create(new { thresholds = new { high = 4 } }) };
        allowed.Headers.Add("X-Demo-Role", "security");
        var response = await _client.SendAsync(allowed);
        var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(4, payload.RootElement.GetProperty("policy").GetProperty("thresholds").GetProperty("high").GetInt32());
    }

    [Fact]
    public async Task IngestsAndNormalizesSemgrepReport()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/ingest")
        {
            Content = JsonContent.Create(new
            {
                projectId = "project-payments",
                tool = "semgrep",
                branch = "feature/report-import",
                commit = "d312a9f",
                report = new { results = new[] { new { check_id = "demo.xss", path = "src/view.js", start = new { line = 12 }, extra = new { severity = "ERROR", message = "Unsafe HTML rendering" } } } }
            })
        };
        request.Headers.Add("X-Demo-Role", "security");
        var response = await _client.SendAsync(request);
        var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(1, payload.RootElement.GetProperty("imported").GetInt32());
        Assert.Equal("project-payments", payload.RootElement.GetProperty("run").GetProperty("project").GetProperty("id").GetString());
    }

    [Fact]
    public async Task RiskExceptionFollowsRequestAndApprovalLifecycle()
    {
        var create = new HttpRequestMessage(HttpMethod.Post, "/api/exceptions")
        {
            Content = JsonContent.Create(new { findingId = "finding-openssl", requestedBy = "Billing team", reason = "Patched base image is undergoing compatibility tests.", compensatingControl = "Workload egress is restricted.", expiresAt = "2099-01-01" })
        };
        create.Headers.Add("X-Demo-Role", "developer");
        var created = await _client.SendAsync(create);
        var createdPayload = await JsonDocument.ParseAsync(await created.Content.ReadAsStreamAsync());
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = createdPayload.RootElement.GetProperty("exception").GetProperty("id").GetString();

        var approve = new HttpRequestMessage(HttpMethod.Patch, $"/api/exceptions/{id}") { Content = JsonContent.Create(new { status = "approved", approvedBy = "Security lead" }) };
        approve.Headers.Add("X-Demo-Role", "security");
        var approved = await _client.SendAsync(approve);
        var approvedPayload = await JsonDocument.ParseAsync(await approved.Content.ReadAsStreamAsync());
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal("approved", approvedPayload.RootElement.GetProperty("exception").GetProperty("status").GetString());
    }

    private async Task<JsonDocument> GetJson(string path)
    {
        var stream = await _client.GetStreamAsync(path);
        return await JsonDocument.ParseAsync(stream);
    }
}
