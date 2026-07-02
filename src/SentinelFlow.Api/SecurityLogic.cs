using System.Text.Json;

namespace SentinelFlow.Api;

public static class SecurityRoles
{
    public const string Security = "security";
    public static readonly string[] WriteRoles = ["security", "developer"];
    public static readonly HashSet<string> ValidFindingStatuses = ["open", "in_progress", "resolved", "accepted", "false_positive"];

    public static string? Require(HttpRequest request, IEnumerable<string> allowed)
    {
        var role = request.Headers.TryGetValue("X-Demo-Role", out var value) ? value.ToString().Trim().ToLowerInvariant() : "manager";
        return allowed.Contains(role) ? role : null;
    }
}

public static class PolicyEngine
{
    private static readonly Dictionary<string, int> SeverityWeight = new() { ["critical"] = 4, ["high"] = 3, ["medium"] = 2, ["low"] = 1, ["info"] = 0 };

    public static PolicyDecision Evaluate(IEnumerable<Finding> findings, IEnumerable<ScannerExecution> scanners, IEnumerable<RiskException> exceptions, Policy policy, DateTimeOffset? now = null)
    {
        var instant = now ?? DateTimeOffset.UtcNow;
        var findingList = findings.ToList();
        var applicable = findingList.Where(finding => finding.Status != "resolved" && !HasActiveException(finding.Id, exceptions, instant)).ToList();
        var counts = new Dictionary<string, int> { ["critical"] = 0, ["high"] = 0, ["medium"] = 0, ["low"] = 0, ["info"] = 0, ["secrets"] = 0 };
        foreach (var finding in applicable)
        {
            counts[finding.Severity] = counts.GetValueOrDefault(finding.Severity) + 1;
            if (finding.Category == "secret") counts["secrets"] += 1;
        }

        var scannerMap = scanners.ToDictionary(scanner => scanner.Type, scanner => scanner.Status);
        var missingScanners = policy.RequiredScanners.Where(type => !scannerMap.TryGetValue(type, out var status) || status != "passed").ToList();
        var violations = new List<string>();
        if (counts["critical"] > policy.Thresholds["critical"]) violations.Add($"{counts["critical"]} critical finding(s); maximum {policy.Thresholds["critical"]}");
        if (counts["high"] > policy.Thresholds["high"]) violations.Add($"{counts["high"]} high finding(s); maximum {policy.Thresholds["high"]}");
        if (counts["secrets"] > policy.Thresholds["secrets"]) violations.Add($"{counts["secrets"]} exposed secret(s); maximum {policy.Thresholds["secrets"]}");
        if (missingScanners.Count > 0) violations.Add($"Required scanners incomplete: {string.Join(", ", missingScanners)}");
        var expired = exceptions.Count(item => item.Status == "approved" && DateTimeOffset.Parse(item.ExpiresAt) <= instant);
        if (policy.BlockOnExpiredException && expired > 0) violations.Add($"{expired} risk exception(s) expired");

        var riskScore = applicable.Sum(finding => SeverityWeight.GetValueOrDefault(finding.Severity));
        return new PolicyDecision(violations.Count == 0 ? "passed" : "blocked", counts, missingScanners, violations, applicable.Count, findingList.Count - applicable.Count, riskScore);
    }

    public static string CalculateSlaDueDate(string severity, string createdAt)
    {
        var days = severity switch { "critical" => 1, "high" => 7, "medium" => 30, "low" => 90, "info" => 180, _ => 30 };
        return DateTimeOffset.Parse(createdAt).AddDays(days).ToString("O");
    }

    private static bool HasActiveException(string findingId, IEnumerable<RiskException> exceptions, DateTimeOffset now) =>
        exceptions.Any(exception => exception.FindingId == findingId && exception.Status == "approved" && DateTimeOffset.Parse(exception.ExpiresAt) > now);
}

public static class SecurityQueries
{
    public static object Summary(SecurityStore store)
    {
        var openFindings = store.Findings.Where(finding => finding.Status != "resolved").ToList();
        var blockedRuns = store.Runs.Count(run => EnrichedRun(store, run).Decision.Decision == "blocked");
        var scannerExecutions = store.Runs.SelectMany(run => run.Scanners).ToList();
        var passedScanners = scannerExecutions.Count(scanner => scanner.Status == "passed");
        return new
        {
            projects = store.Projects.Count,
            openFindings = openFindings.Count,
            criticalFindings = openFindings.Count(finding => finding.Severity == "critical"),
            blockedRuns,
            overdueFindings = openFindings.Count(finding => DateTimeOffset.Parse(finding.SlaDueAt) < DateTimeOffset.UtcNow),
            coverage = scannerExecutions.Count > 0 ? (int)Math.Round((double)passedScanners / scannerExecutions.Count * 100) : 0,
            severity = new[] { "critical", "high", "medium", "low" }.Select(severity => new { severity, count = openFindings.Count(finding => finding.Severity == severity) }),
            trend = new[] { new { label = "May 20", opened = 7, resolved = 3 }, new { label = "May 27", opened = 5, resolved = 6 }, new { label = "Jun 03", opened = 8, resolved = 5 }, new { label = "Jun 10", opened = 4, resolved = 7 } }
        };
    }

    public static EnrichedRun EnrichedRun(SecurityStore store, PipelineRun run)
    {
        var project = store.Projects.FirstOrDefault(item => item.Id == run.ProjectId);
        var findings = store.Findings.Where(item => item.RunId == run.Id).ToList();
        var exceptions = store.Exceptions.Where(item => item.ProjectId == run.ProjectId).ToList();
        var policy = store.Policies.FirstOrDefault(item => item.Enabled) ?? store.Policies[0];
        return new EnrichedRun(run.Id, run.ProjectId, run.Branch, run.Commit, run.Author, run.Status, run.CreatedAt, run.DurationSeconds, run.Scanners, project, PolicyEngine.Evaluate(findings, run.Scanners, exceptions, policy));
    }

    public static PipelineRun UpsertRun(SecurityStore store, Project project, IngestRequest input)
    {
        var runId = string.IsNullOrWhiteSpace(input.RunId) ? $"run-{Guid.NewGuid()}" : input.RunId;
        var run = store.Runs.FirstOrDefault(item => item.Id == runId);
        if (run is not null) return run;
        run = new PipelineRun
        {
            Id = runId,
            ProjectId = project.Id,
            Branch = string.IsNullOrWhiteSpace(input.Branch) ? project.DefaultBranch : input.Branch,
            Commit = string.IsNullOrWhiteSpace(input.Commit) ? "manual" : input.Commit,
            Author = string.IsNullOrWhiteSpace(input.Author) ? "Scanner ingestion" : input.Author,
            CreatedAt = DateTimeOffset.UtcNow.ToString("O")
        };
        store.Runs.Insert(0, run);
        return run;
    }
}

public static class FindingNormalizer
{
    public static List<Finding> Normalize(IngestRequest input, Project project, string runId)
    {
        if (input.Report.ValueKind != JsonValueKind.Object) return [];
        return (input.Tool ?? "").ToLowerInvariant() switch
        {
            "semgrep" => NormalizeSemgrep(input.Report, project, runId),
            _ => []
        };
    }

    public static string ScannerType(string? tool) => (tool ?? "").ToLowerInvariant() switch
    {
        "semgrep" => "sast",
        "trivy-sca" => "sca",
        "trivy-container" => "container",
        "gitleaks" => "secrets",
        _ => "sast"
    };

    private static List<Finding> NormalizeSemgrep(JsonElement report, Project project, string runId)
    {
        if (!report.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array) return [];
        var now = DateTimeOffset.UtcNow.ToString("O");
        return results.EnumerateArray().Select(result =>
        {
            var extra = result.TryGetProperty("extra", out var extraElement) ? extraElement : default;
            var semgrepSeverity = extra.ValueKind == JsonValueKind.Object && extra.TryGetProperty("severity", out var severityElement) ? severityElement.GetString() : "WARNING";
            var severity = semgrepSeverity == "ERROR" ? "high" : semgrepSeverity == "INFO" ? "low" : "medium";
            var path = result.TryGetProperty("path", out var pathElement) ? pathElement.GetString() : "unknown";
            var line = result.TryGetProperty("start", out var start) && start.TryGetProperty("line", out var lineElement) ? lineElement.GetInt32() : 1;
            var title = extra.ValueKind == JsonValueKind.Object && extra.TryGetProperty("message", out var message) ? message.GetString() : "Semgrep finding";
            return new Finding
            {
                Id = $"finding-{Guid.NewGuid()}",
                ProjectId = project.Id,
                RunId = runId,
                Scanner = "sast",
                Severity = severity,
                Category = "code",
                Title = title ?? "Semgrep finding",
                Location = $"{path}:{line}",
                Owner = project.Owner,
                SlaDueAt = PolicyEngine.CalculateSlaDueDate(severity, now)
            };
        }).ToList();
    }
}
