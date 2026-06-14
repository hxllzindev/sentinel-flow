# Demo script

Suggested duration: 6 minutes.

## 1. Overview

Explain that Sentinel Flow is the control plane around existing scanners, not another scanner. Show protected projects, open findings, blocked runs and coverage.

## 2. Pipeline decision

Open Payments API run `run-1042`. Show five security gates and the blocked policy decision caused by a committed secret and critical exposure.

## 3. Finding triage

Open the SQL injection finding. Assign it to a remediation squad and move it to `in_progress`. Switch to manager role and demonstrate that writes are denied.

## 4. Policy as code

Open Policies. Explain critical, high and secret thresholds plus required-scanner coverage. Change a threshold as security engineer and show runs reevaluated.

## 5. Risk exception

Request an exception for a finding with a reason, compensating control and expiration. Switch to security engineer and approve it. Explain that expired exceptions block again automatically.

## 6. Ingestion

Use the prefilled Semgrep JSON in Ingest report. Show the normalized finding appearing in the backlog and the new run receiving a policy decision.

## Close

"The platform turns scanner output into an operational security process: ownership, SLA, policy, evidence and risk governance."
