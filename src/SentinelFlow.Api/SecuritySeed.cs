namespace SentinelFlow.Api;

public static class SecuritySeed
{
    public static SecurityStore CreateStore()
    {
        var createdAt = DateTimeOffset.UtcNow.AddDays(-4).ToString("O");
        var store = new SecurityStore
        {
            Projects =
            [
                new("project-payments", "Payments API", "Payments remediation squad", "production", "main"),
                new("project-portal", "Customer Portal", "Portal team", "production", "main"),
                new("project-worker", "Invoice Worker", "Platform team", "staging", "main")
            ],
            Policies =
            [
                new()
                {
                    Id = "policy-default",
                    Name = "Production merge policy",
                    Description = "Blocks releases with exploitable risk or incomplete security coverage.",
                    Enabled = true
                }
            ],
            Runs =
            [
                new()
                {
                    Id = "run-1042",
                    ProjectId = "project-payments",
                    Branch = "release/2026.07",
                    Commit = "a3f71de",
                    Author = "CI pipeline",
                    Status = "blocked",
                    CreatedAt = createdAt,
                    DurationSeconds = 312,
                    Scanners =
                    [
                        new("sast", "passed", 2, 54),
                        new("sca", "passed", 1, 41),
                        new("secrets", "passed", 1, 16),
                        new("container", "passed", 1, 73)
                    ]
                },
                new()
                {
                    Id = "run-1037",
                    ProjectId = "project-portal",
                    Branch = "main",
                    Commit = "9f10b2c",
                    Author = "CI pipeline",
                    Status = "review",
                    CreatedAt = DateTimeOffset.UtcNow.AddDays(-1).ToString("O"),
                    DurationSeconds = 228,
                    Scanners =
                    [
                        new("sast", "passed", 1, 48),
                        new("sca", "passed", 0, 36),
                        new("secrets", "passed", 0, 11),
                        new("container", "passed", 0, 51),
                        new("dast", "passed", 0, 94)
                    ]
                }
            ]
        };

        store.Findings.AddRange(
        [
            Finding("finding-sqli", "project-payments", "run-1042", "sast", "critical", "code", "Parameterized query missing on payment lookup", "src/payments/PaymentRepository.cs:88", "open", "Payments remediation squad", createdAt),
            Finding("finding-openssl", "project-payments", "run-1042", "sca", "high", "dependency", "OpenSSL CVE in base image dependency chain", "Dockerfile:1", "open", "Platform team", createdAt),
            Finding("finding-secret", "project-payments", "run-1042", "secrets", "high", "secret", "Potential cloud token committed in sample config", "samples/appsettings.Development.json:12", "open", "Security team", createdAt),
            Finding("finding-xss", "project-portal", "run-1037", "sast", "medium", "code", "Untrusted markdown rendered without sanitization", "src/pages/Announcements.tsx:44", "in_progress", "Portal team", DateTimeOffset.UtcNow.AddDays(-1).ToString("O"))
        ]);

        store.Audit.Add(AuditEvent.Create("policy_evaluated", "system", new { runId = "run-1042", decision = "blocked" }));
        return store;
    }

    private static Finding Finding(string id, string projectId, string runId, string scanner, string severity, string category, string title, string location, string status, string owner, string createdAt) => new()
    {
        Id = id,
        ProjectId = projectId,
        RunId = runId,
        Scanner = scanner,
        Severity = severity,
        Category = category,
        Title = title,
        Location = location,
        Status = status,
        Owner = owner,
        SlaDueAt = PolicyEngine.CalculateSlaDueDate(severity, createdAt)
    };
}
