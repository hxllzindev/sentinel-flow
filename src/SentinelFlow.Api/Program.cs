using System.Text.Json;
using SentinelFlow.Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(SecuritySeed.CreateStore());

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new { status = "ok", stack = ".NET 10" }));

app.MapGet("/api/summary", (SecurityStore store) => Results.Ok(SecurityQueries.Summary(store)));
app.MapGet("/api/projects", (SecurityStore store) => Results.Ok(new { projects = store.Projects }));
app.MapGet("/api/runs", (SecurityStore store) => Results.Ok(new { runs = store.Runs.Select(run => SecurityQueries.EnrichedRun(store, run)) }));
app.MapGet("/api/runs/{id}", (string id, SecurityStore store) =>
{
    var run = store.Runs.FirstOrDefault(item => item.Id == id);
    return run is null
        ? Results.NotFound(new { error = "Run not found." })
        : Results.Ok(new { run = SecurityQueries.EnrichedRun(store, run), findings = store.Findings.Where(item => item.RunId == run.Id) });
});

app.MapGet("/api/findings", (HttpRequest request, SecurityStore store) =>
{
    var query = request.Query;
    var findings = store.Findings.Where(finding =>
        (!query.TryGetValue("severity", out var severity) || finding.Severity == severity) &&
        (!query.TryGetValue("status", out var status) || finding.Status == status) &&
        (!query.TryGetValue("projectId", out var projectId) || finding.ProjectId == projectId));
    return Results.Ok(new { findings });
});

app.MapPatch("/api/findings/{id}", async (string id, HttpRequest request, SecurityStore store) =>
{
    var actorRole = SecurityRoles.Require(request, SecurityRoles.WriteRoles);
    if (actorRole is null) return Results.Json(new { error = "Insufficient role for this operation." }, statusCode: 403);
    var finding = store.Findings.FirstOrDefault(item => item.Id == id);
    if (finding is null) return Results.NotFound(new { error = "Finding not found." });
    var input = await JsonSerializer.DeserializeAsync<FindingUpdate>(request.Body, JsonDefaults.Options) ?? new FindingUpdate();
    if (input.Status is not null && !SecurityRoles.ValidFindingStatuses.Contains(input.Status)) return Results.Json(new { error = "Invalid status." }, statusCode: 422);
    if (input.Status is not null) finding.Status = input.Status;
    if (!string.IsNullOrWhiteSpace(input.Owner)) finding.Owner = input.Owner[..Math.Min(input.Owner.Length, 120)];
    store.Audit.Insert(0, AuditEvent.Create("finding_updated", actorRole, new { findingId = finding.Id, finding.Status, finding.Owner }));
    return Results.Ok(new { finding });
});

app.MapGet("/api/policies", (SecurityStore store) => Results.Ok(new { policies = store.Policies }));
app.MapPut("/api/policies/{id}", async (string id, HttpRequest request, SecurityStore store) =>
{
    var actorRole = SecurityRoles.Require(request, [SecurityRoles.Security]);
    if (actorRole is null) return Results.Json(new { error = "Insufficient role for this operation." }, statusCode: 403);
    var policy = store.Policies.FirstOrDefault(item => item.Id == id);
    if (policy is null) return Results.NotFound(new { error = "Policy not found." });
    var input = await JsonSerializer.DeserializeAsync<PolicyUpdate>(request.Body, JsonDefaults.Options) ?? new PolicyUpdate();
    foreach (var threshold in input.Thresholds)
    {
        if (!Policy.ValidThresholds.Contains(threshold.Key) || threshold.Value < 0) return Results.Json(new { error = $"Invalid {threshold.Key} threshold." }, statusCode: 422);
        policy.Thresholds[threshold.Key] = threshold.Value;
    }
    store.Audit.Insert(0, AuditEvent.Create("policy_updated", actorRole, new { policyId = policy.Id, policy.Thresholds }));
    return Results.Ok(new { policy });
});

app.MapPost("/api/evaluate/{id}", (string id, SecurityStore store) =>
{
    var run = store.Runs.FirstOrDefault(item => item.Id == id);
    return run is null ? Results.NotFound(new { error = "Run not found." }) : Results.Ok(new { run = SecurityQueries.EnrichedRun(store, run) });
});

app.MapGet("/api/exceptions", (SecurityStore store) => Results.Ok(new { exceptions = store.Exceptions }));
app.MapPost("/api/exceptions", async (HttpRequest request, SecurityStore store) =>
{
    var actorRole = SecurityRoles.Require(request, SecurityRoles.WriteRoles);
    if (actorRole is null) return Results.Json(new { error = "Insufficient role for this operation." }, statusCode: 403);
    var input = await JsonSerializer.DeserializeAsync<ExceptionRequest>(request.Body, JsonDefaults.Options) ?? new ExceptionRequest();
    var finding = store.Findings.FirstOrDefault(item => item.Id == input.FindingId);
    if (finding is null) return Results.Json(new { error = "A valid finding is required." }, statusCode: 422);
    if (string.IsNullOrWhiteSpace(input.Reason) || string.IsNullOrWhiteSpace(input.CompensatingControl) || input.ExpiresAt is null) return Results.Json(new { error = "Reason, compensating control and expiration are required." }, statusCode: 422);
    if (!DateTimeOffset.TryParse(input.ExpiresAt, out var expiresAt) || expiresAt <= DateTimeOffset.UtcNow) return Results.Json(new { error = "Expiration must be a valid future date." }, statusCode: 422);
    var exception = RiskException.Create(finding, input, expiresAt);
    store.Exceptions.Insert(0, exception);
    store.Audit.Insert(0, AuditEvent.Create("exception_requested", actorRole, new { exceptionId = exception.Id, findingId = finding.Id }));
    return Results.Created($"/api/exceptions/{exception.Id}", new { exception });
});

app.MapPatch("/api/exceptions/{id}", async (string id, HttpRequest request, SecurityStore store) =>
{
    var actorRole = SecurityRoles.Require(request, [SecurityRoles.Security]);
    if (actorRole is null) return Results.Json(new { error = "Insufficient role for this operation." }, statusCode: 403);
    var exception = store.Exceptions.FirstOrDefault(item => item.Id == id);
    if (exception is null) return Results.NotFound(new { error = "Exception not found." });
    var input = await JsonSerializer.DeserializeAsync<ExceptionReview>(request.Body, JsonDefaults.Options) ?? new ExceptionReview();
    if (input.Status is not ("approved" or "rejected")) return Results.Json(new { error = "Status must be approved or rejected." }, statusCode: 422);
    exception.Status = input.Status;
    exception.ApprovedBy = string.IsNullOrWhiteSpace(input.ApprovedBy) ? "Security reviewer" : input.ApprovedBy[..Math.Min(input.ApprovedBy.Length, 120)];
    store.Audit.Insert(0, AuditEvent.Create("exception_reviewed", actorRole, new { exceptionId = exception.Id, exception.Status }));
    return Results.Ok(new { exception });
});

app.MapPost("/api/ingest", async (HttpRequest request, SecurityStore store) =>
{
    var actorRole = SecurityRoles.Require(request, [SecurityRoles.Security]);
    if (actorRole is null) return Results.Json(new { error = "Insufficient role for this operation." }, statusCode: 403);
    var input = await JsonSerializer.DeserializeAsync<IngestRequest>(request.Body, JsonDefaults.Options) ?? new IngestRequest();
    var project = store.Projects.FirstOrDefault(item => item.Id == input.ProjectId);
    if (project is null) return Results.Json(new { error = "A valid project is required." }, statusCode: 422);
    var run = SecurityQueries.UpsertRun(store, project, input);
    var imported = FindingNormalizer.Normalize(input, project, run.Id);
    store.Findings.InsertRange(0, imported);
    var scannerType = imported.FirstOrDefault()?.Scanner ?? FindingNormalizer.ScannerType(input.Tool);
    var scanner = run.Scanners.FirstOrDefault(item => item.Type == scannerType);
    if (scanner is null) run.Scanners.Add(new ScannerExecution(scannerType, "passed", imported.Count, input.DurationSeconds));
    else { scanner.Status = "passed"; scanner.Findings += imported.Count; }
    run.Status = SecurityQueries.EnrichedRun(store, run).Decision.Decision;
    store.Audit.Insert(0, AuditEvent.Create("report_ingested", actorRole, new { input.Tool, runId = run.Id, findings = imported.Count }));
    return Results.Created($"/api/runs/{run.Id}", new { run = SecurityQueries.EnrichedRun(store, run), imported = imported.Count });
});

app.MapGet("/api/audit", (SecurityStore store) => Results.Ok(new { events = store.Audit.Take(50) }));

app.Run();

public partial class Program;
