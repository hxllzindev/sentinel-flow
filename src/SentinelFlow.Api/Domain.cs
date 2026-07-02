using System.Text.Json;

namespace SentinelFlow.Api;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}

public sealed class SecurityStore
{
    public List<Project> Projects { get; init; } = [];
    public List<PipelineRun> Runs { get; init; } = [];
    public List<Finding> Findings { get; init; } = [];
    public List<Policy> Policies { get; init; } = [];
    public List<RiskException> Exceptions { get; init; } = [];
    public List<AuditEvent> Audit { get; init; } = [];
}

public sealed record Project(string Id, string Name, string Owner, string Environment, string DefaultBranch);
public sealed record ScannerExecution(string Type, string Status, int Findings, int DurationSeconds)
{
    public string Status { get; set; } = Status;
    public int Findings { get; set; } = Findings;
}

public sealed class PipelineRun
{
    public required string Id { get; init; }
    public required string ProjectId { get; init; }
    public required string Branch { get; init; }
    public required string Commit { get; init; }
    public required string Author { get; init; }
    public string Status { get; set; } = "review";
    public required string CreatedAt { get; init; }
    public int DurationSeconds { get; init; }
    public List<ScannerExecution> Scanners { get; init; } = [];
}

public sealed class Finding
{
    public required string Id { get; init; }
    public required string ProjectId { get; init; }
    public required string RunId { get; init; }
    public required string Scanner { get; init; }
    public required string Severity { get; init; }
    public required string Category { get; init; }
    public required string Title { get; init; }
    public required string Location { get; init; }
    public string Status { get; set; } = "open";
    public string Owner { get; set; } = "Unassigned";
    public required string SlaDueAt { get; init; }
}

public sealed class Policy
{
    public static readonly HashSet<string> ValidThresholds = ["critical", "high", "secrets"];
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public bool Enabled { get; init; }
    public Dictionary<string, int> Thresholds { get; init; } = new() { ["critical"] = 0, ["high"] = 2, ["secrets"] = 0 };
    public List<string> RequiredScanners { get; init; } = ["sast", "sca", "secrets", "container", "dast"];
    public bool BlockOnExpiredException { get; init; } = true;
}

public sealed class RiskException
{
    public required string Id { get; init; }
    public required string FindingId { get; init; }
    public required string ProjectId { get; init; }
    public string Status { get; set; } = "pending";
    public required string RequestedBy { get; init; }
    public string? ApprovedBy { get; set; }
    public required string Reason { get; init; }
    public required string CompensatingControl { get; init; }
    public required string CreatedAt { get; init; }
    public required string ExpiresAt { get; init; }

    public static RiskException Create(Finding finding, ExceptionRequest input, DateTimeOffset expiresAt) => new()
    {
        Id = $"exception-{Guid.NewGuid()}",
        FindingId = finding.Id,
        ProjectId = finding.ProjectId,
        RequestedBy = Trim(input.RequestedBy, "Current user", 120),
        Reason = Trim(input.Reason, "No reason supplied", 600),
        CompensatingControl = Trim(input.CompensatingControl, "No compensating control supplied", 600),
        CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
        ExpiresAt = expiresAt.ToUniversalTime().ToString("O")
    };

    private static string Trim(string? value, string fallback, int max) => string.IsNullOrWhiteSpace(value) ? fallback : value[..Math.Min(value.Length, max)];
}

public sealed record AuditEvent(string Id, string Action, string ActorRole, object Details, string CreatedAt)
{
    public static AuditEvent Create(string action, string actorRole, object details) => new(Guid.NewGuid().ToString(), action, actorRole, details, DateTimeOffset.UtcNow.ToString("O"));
}

public sealed record PolicyDecision(string Decision, Dictionary<string, int> Counts, List<string> MissingScanners, List<string> Violations, int EvaluatedFindings, int ExemptedFindings, int RiskScore);
public sealed record EnrichedRun(string Id, string ProjectId, string Branch, string Commit, string Author, string Status, string CreatedAt, int DurationSeconds, List<ScannerExecution> Scanners, Project? Project, PolicyDecision Decision);

public sealed class FindingUpdate { public string? Status { get; init; } public string? Owner { get; init; } }
public sealed class PolicyUpdate { public Dictionary<string, int> Thresholds { get; init; } = []; }
public sealed class ExceptionRequest { public string? FindingId { get; init; } public string? RequestedBy { get; init; } public string? Reason { get; init; } public string? CompensatingControl { get; init; } public string? ExpiresAt { get; init; } }
public sealed class ExceptionReview { public string? Status { get; init; } public string? ApprovedBy { get; init; } }
public sealed class IngestRequest
{
    public string? ProjectId { get; init; }
    public string? Tool { get; init; }
    public string? RunId { get; init; }
    public string? Branch { get; init; }
    public string? Commit { get; init; }
    public string? Author { get; init; }
    public int DurationSeconds { get; init; }
    public JsonElement Report { get; init; }
}
