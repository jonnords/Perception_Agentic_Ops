# Perception Evidence Workspace

## Customer quick start

This customer evaluation package includes the v2 workspace, agent-linked
Operational Loops & Outcomes, optional AI settings, and automatic best-effort
Defender investigation recovery when the API returns HTTP 414.

1. Confirm your organisation's preview access, permissions and approval to use
   the app. Install PowerShell 7.2+ and Azure CLI on Windows. Node.js 22+ is
   needed only for optional systemic model synthesis.
2. Compare the downloaded ZIP's SHA-256 hash (`Get-FileHash -Algorithm SHA256`)
   with the supplied `.zip.sha256` file received through your trusted
   distribution channel. Extract the trusted ZIP into a new local folder.
   Do not extract it over an existing tenant working folder.
3. Open PowerShell 7 in the extracted folder and run:

   ```powershell
   .\Start-App.ps1
   ```

   Open `http://127.0.0.1:8765` if the browser does not open automatically.
   All seven reports initially show **Not generated**. That is intentional:
   the package contains no tenant evidence or configured model endpoint.
   Opening it does not sign in, collect data, run an agent or call a model.
4. When ready to collect your own evidence, stop the server with Ctrl+C, sign
   in to your approved tenant, then restart with an explicit refresh:

   ```powershell
   az login --tenant <your-tenant-id>
   .\Start-App.ps1 -Refresh
   ```

   See **Sign in and collect** below for the required Perception access.
   Defender comparisons and model analysis require additional permissions
   and explicit commands; neither runs as part of this basic refresh.

**Important limitations:** This is a local, single-user evaluation tool, not
a production-hosted service or a security assurance. Do not expose its port
through a tunnel or reverse proxy. HTTP 414 recovery improves discovery but
does not guarantee complete tenant history. Reports keep missing evidence and
collection errors visible. Optional model operations submit selected evidence
to your configured deployment and can incur charges.

Share only the clean ZIP and its checksum, never a folder that has been used
with a tenant. Generated reports, local configuration and token files remain
private to your customer-approved working directory.

## Local v2 navigation and presentation

The workspace and standalone reports share report navigation, typography, colors
and spacing. In-page section links remain within the report; cross-report links
open the appropriate workspace view. Standalone HTML also supports sibling-file
navigation when opened without the local server. Reports unavailable when the
presentation was updated are marked as not generated in offline navigation.
The workspace uses an icon-based navigation rail, direct report cards with
explicit saved/not-generated states, and a compact setup section that expands
automatically for an empty workspace. On smaller screens the navigation becomes
a horizontally scrollable row. Reports share blue/teal accents, clear metric
cards and consistent filters, tables and evidence readers. Icons are bundled
inline; no remote fonts or UI libraries are loaded. Focus indicators and
reduced-motion preferences are supported. Styling does not change verdict,
availability or execution-status semantics.
Report switches use replacement iframe navigation so browser Back and Forward
track the selected view instead of duplicate frame loads. Cancelled local
response delivery is logged without terminating the listener.

After a presentation update, refresh the browser page to load the new workspace
code. Use **Reload saved reports** to reload report files without collecting data
or calling a model.

The **Lay of the land** summary and **Workflow status** table belong only to
Freshness / Run Quality. Operational Briefing starts with agent-reported findings
and retains its workflow, agent, time, outcome and incident/input filters.

The Production Environment view has its own responsive dashboard presentation:
direct session/agent links, grouped metric cards, a sticky section navigator,
and clearer tables and session rows. Session search and state filtering retain
their existing behavior. Charcoal text and light neutral badges provide clear
contrast; color is retained for primary actions and status badges.
Session/run `succeeded` and `completed` badges use the same light-green
execution-success style; failed/cancelled states use the error style. Other
states use light neutral badges without inline color overrides. These lifecycle
badges do not certify security outcomes.
This is a saved snapshot, not a live telemetry feed;
presentation updates do not collect evidence or run AI analysis.

To update existing HTML after changing the shared presentation layer, without
regenerating analyses:

```powershell
.\Update-PerceptionReportPresentation.ps1
```

All seven report generators apply the same shared presentation automatically.
This operation changes HTML presentation only, not report JSON or embedded
evidence. Maintainers can additionally use `-RefreshManifest` after local source
changes to refresh the v2 source-file hashes. The original customer ZIP is not
modified, and real configuration and tenant outputs remain excluded from the
source manifest.

Customer evaluation preview: one local web workspace for environment evidence,
operational briefings, freshness, operational loop coverage, agent behavior, systemic threat hypotheses and
Defender investigation comparisons. This is not a hosted service, an independent
security verdict or a guarantee of complete tenant coverage. Confirm your
organisation's licensing, support and approval requirements before external
redistribution or production use.

## Requirements

- Windows with PowerShell 7.2 or later (`pwsh`).
- Azure CLI for tenant data collection and automatic Entra token acquisition.
- Your own Perception access and tenant-approved API permissions.
- Optional: Node.js 22 or later and your own Azure model deployment for systemic
  synthesis. Behavior analysis also uses your own Azure deployment.
- A customer-approved local directory for generated tenant-sensitive reports.

No tenant data, tokens, API keys, developer endpoints, configured customer tenant
or Council application is shipped. `manifest.json` lists the packaged files and
their SHA-256 hashes. Verify the archive hash through your distribution channel.
If Windows blocks downloaded scripts, unblock the trusted ZIP before extracting;
the app does not change machine execution policy.

## Open the workspace

Extract the ZIP, open PowerShell 7 in that directory, and run:

```powershell
.\Start-App.ps1
```

Your browser opens `http://127.0.0.1:8765`. A clean installation shows setup
instructions and explicit "Not generated" states, not sample customer evidence.
No login, collection or paid model request occurs merely by opening the app.
All report views share one navigation shell. Existing standalone scripts and HTML
exports remain available. Stop the app with Ctrl+C before restarting on the same
port, or explicitly choose another port with `-Port`.

## Sign in and collect

```powershell
az login --tenant <your-tenant-id>
.\Start-App.ps1 -Refresh
```

Tokens are acquired automatically from the signed-in Azure CLI context; do not
copy tokens into code, browser fields or configuration. Optionally copy
`perception.config.example.json` to `perception.config.json` and set `tenantId`
to pin the intended tenant. An empty tenant ID uses the selected CLI context.
Authentication errors do not switch to a different tenant, credential or token
file automatically.

Perception requires the appropriate service access and consent for
`https://api.securitycopilot.microsoft.com/Perception.Operate.All`. Your tenant
administrator must approve the identity and API permissions. Collection and
report generation run locally. Generated HTML/JSON/CSV contain tenant data.

## Temporary Defender investigation discovery recovery

If session pagination returns HTTP 414 (URI Too Long), the Defender investigation
collector automatically tries separate queries for API `status` values observed
in the pages already retrieved. This can recover investigations hidden behind a
large volume of other sessions without requiring you to find their session IDs.
Rerun your existing `New-PerceptionDefenderInvestigationReport.ps1` command;
no new option or authentication change is needed.

The collector deduplicates sessions and collects their evidence and Defender
comparisons normally. It follows usable continuation links unchanged, limits
each fallback query to `MaxSessionPagesPerState`, and shares the existing overall
`MaxSessionPagesPerState * 6` page budget across normal and fallback queries.
Only observed API status values are used; UI lifecycle labels are not substituted.

**This does not fix server pagination or establish complete coverage.** The
report retains the original error and any failed status queries, keeps both
`CollectionComplete` and `SessionDiscoveryComplete` false, and declares
`AllSessionsWithStatusFallback` scope. The HTML/console coverage notice shows
additional sessions recovered. JSON `Source` records
`StatusDiscoveryFallbackUsed`, `StatusDiscoveryFallbackStatuses`,
`StatusDiscoveryFallbackAdditionalSessions`, and `PagesReadByState`.
Unseen statuses and unread continuation pages may still contain investigations.

Normal successful pagination is unchanged. For known sessions,
`-SessionId 'session-id-1', 'session-id-2'` still bypasses discovery entirely and
does not invoke the fallback. Graph token-file overrides remain explicit only;
never include token files in shared packages.

## Operational Loops & Outcomes

Open **Operational Loops & Outcomes** in the workspace, or start directly with
`.\Start-App.ps1 -OperationalLoops`. When a saved snapshot exists, the launcher
regenerates this local evidence view alongside Briefing and Freshness. To
generate it separately without collection or model requests:

```powershell
.\New-PerceptionOperationalLoopsReport.ps1 -NoOpen
```

The saved HTML and JSON map readable artifacts for review across **Sense,
Understand, Decide, Engineer, Act, Verify and Learn**. This is evidence coverage,
not a loop-completion score or certification that work happened. Not every entry
flow requires all seven stages. Suggested alert-led, threat-led and exposure-led
flows are workflow-derived, not proven purpose; hunts and validation are not
inferred from titles or repeat runs. Search, flow and evidence filters apply to
the coverage table and its JSON export. Select a group to review exact source
artifacts and contextual transcripts, including collection gaps.

The **From faster tasks to verified outcomes** graph combines the target
operating model with a current-evidence overlay. It shows evidence-directed
coordination, human authority, accountable execution and a feedback path from
learning to earlier stages. Its annotations explain the intended alternatives
to queue-heavy tier escalation, repeated per-alert analysis and unverified
closure. These are design mechanisms, not claims of implemented orchestration
or measured improvement. The ordered seven-stage diagram is conceptual, not a
required execution sequence for every flow.

Each node counts **filtered evidence groups**, not artifacts, completed stages
or a single connected loop. The graph follows the same filters as the table;
an empty selection keeps the target model visible without inventing evidence.
To validate changes in queue time, effort/cost or risk, collect linked handoff,
decision, execution, same-scope verification and reuse records and compare them
against an appropriate baseline. Current unknown metrics remain unknown.

The **Agent-linked playbooks** section maps five operating flows to the saved
playbook catalog and registered agents, including agents with no retained runs.
Alert, threat and exposure dependencies come from the catalog's exact agent
definitions; additional role-based mappings (including Outcome Assurance,
hunting and validation) are labeled separately. Only the known `Global.` prefix
on `Microsoft.Defender.*` definition names is normalized; friendly names are
never used to infer identities. Multiple registered versions remain visible,
and disabled, missing or unknown registry states are not treated as ready.

Expand an agent to inspect its observed runs and transcripts. Shared session
outputs are separate from run context, since this report cannot attribute them
to individual agents. Activity follows the evidence filters; the available
catalog remains visible. A run appearing under an agent is not proof that each
mapped flow executed, and counts shared across cards are not additive.
Opening the cards does not launch agents, submit prompts, schedule work or
certify outcomes. The collector retains catalog data in the snapshot; the
operational report includes it in JSON, but the coverage export remains limited
to stage evidence. Older snapshots show an explicit catalog-not-collected state.

A separate **DEMO ONLY - FICTIONAL DATA - NOT YOUR TENANT** Sankey illustrates
an alert-led cohort of 1,000 imagined work items. **All 1,000 pass through
agentic resolution / disposition checks**. The large band contains three
outcome types: 700 Defender resolutions confirmed, 200 no-action dispositions
checked, and 100 unresolved or uncertain items flagged for investigation.
Missing evidence, failed responses and uncertainty require flags, not assumed
resolution. Checking a no-action disposition is not a claim of risk reduction.
Defender blocking/containment can occur before or during triage; it does not
wait for later investigation, decision or human-led action stages.
The agentic system checks the result, rather than assuming action success
means resolution. Colors in the large band represent check outcomes, not
predictions at detection. This is a target responsibility, not a claim that
this report implements or observes agentic checking.
The human-led route sends 20 items to engineering, 5 of which await an owner;
the remaining 15 reach action, with 12 proceeding to verification and 3 failing.
Of those, 12 return to agentic rechecking: 10 reach verified closure and 2 proceed
to selected learning. Other branches show investigation closure and approval or
ownership waits. Visible example cards explain early protection, cohort-wide
checking, outcome types, flagging and follow-up. These illustrate possible capabilities,
not enabled tenant automation; support, configuration, permissions, policy and
required approvals still govern responses.
Verified closure and selected learning are separate outcomes;
routine evidence retention does not count as an explicit learning workflow.
These are fictional illustration choices, not operational benchmarks.
Widths are proportional to fictional work-item counts; counts balance at every
branch, using one linear scale even for very thin downstream bands. This is not
tenant data, measured performance or a mandatory workflow.
The demo is independent of real snapshot filters and is excluded from report
JSON and coverage exports. A fictional flow-count table provides an accessible
alternative; smaller screens can scroll the chart horizontally. The demo ends
with an explicit boundary before real snapshot evidence resumes.

Correlation is limited to one retained snapshot:

- Exactly one valid `loopId=<id>` tag declares a link across sessions. IDs are
  case-sensitive, 1-128 ASCII letters/digits/periods/underscores/colons/hyphens,
  starting with a letter or digit. This declaration does not prove outcomes.
- Otherwise, exactly one numeric `input:incident=<id>` or
  `input:defenderIncidentId=<id>` (1-32 digits, exact value) forms an incident
  **candidate**, not a confirmed loop. Invalid or conflicting loop IDs never
  fall back to merging on an incident.
- Other inputs, broad subscriptions, similar titles and shared entities do not
  join sessions. Ambiguous identifiers remain session-scoped with warnings.
- Optional `loopFlow=alert-led`, `threat-led`, `exposure-led`, `hunt-led` or
  `validation-led` declares an entry flow. Invalid or conflicting flow tags are
  surfaced rather than silently replaced with an inferred flow.

Mappings (version 1): triage maps to Sense/Understand; incident investigation
and identity assessment to Understand; article analysis to Sense/Understand;
posture prioritization to Engineer; reconnaissance to Understand. These mappings
identify artifacts to inspect, not completed stages. Transcripts alone and
unavailable-source/output summaries are context only.

Approval, accountable action, same-scope verification and incorporated learning
need structured records not collected here. Successful runs, recommendations,
repeats and retained logs do not substitute for them. Closure rate, verified
risk reductions, ownership and handoff dwell remain unknown / not calculated,
not zero. Missing evidence is not a stalled-loop or no-action finding.

## Optional Defender comparisons

```powershell
.\Start-App.ps1 -Refresh -IncludeDefender
# Or generate just this report:
.\New-PerceptionDefenderInvestigationReport.ps1
```

Microsoft Graph requires `SecurityIncident.Read.All` (or appropriate higher
incident-read permission), tenant consent and suitable Defender access. If
Azure CLI cannot obtain the required delegated permission, resolve consent and
sign in with the required Graph scope in the intended tenant. The app cannot
grant permissions or bypass tenant policy. An API denial is not evidence that
an incident is benign.

Only as an explicit last resort:

```powershell
.\New-PerceptionDefenderInvestigationReport.ps1 -GraphTokenPath .\graph-token.txt
```

That file must contain a valid, unexpired Graph incident-read token. It is never
discovered automatically and must never be shared, committed or packaged.
`-GraphTokenPath` on the launcher requires `-IncludeDefender`.

## Optional model analysis

### AI Settings in the workspace

Open **AI Settings** in the navigation (or
`http://127.0.0.1:8765/#view=ai-settings`). Enter your complete Azure endpoint,
deployment name, Responses/chat API format and optional model tenant override.
The advanced token-audience setting supports both approved Azure audiences.
The current audience is preserved when settings are loaded and saved.

**Save settings** writes the existing local `perception.config.json` atomically,
or the file selected with the runner's `-ConfigurationPath`. It preserves the
top-level Perception tenant pin. Validation failures leave the previous file
unchanged. Saved settings take effect without restarting the runner. Saving
does not request a token, call a model, collect data or regenerate reports.
An initial save requires both an endpoint and deployment.

The authentication panel reads only cached Azure CLI account metadata. It
does not validate token expiry, prove model access or start interactive login.
Run `az login --tenant <your-tenant-id>` in a terminal and select **Reload
settings** after changing the CLI context. Tokens and API keys are never
accepted, returned to the browser or stored in the configuration.

**Test connection** is optional and requires its own explicit charge consent
before each request. It tests the current form values, including unsaved edits,
with one fixed synthetic prompt, not report evidence. It does not save settings
or regenerate reports. The model deployment may charge for the request using
its default output budget; a timed-out request may still incur charges. The
test rejects redirects, incomplete responses and invalid connection-check
answers. Provider response/error bodies are not exposed to the browser.

To regenerate AI reports, continue using the explicit command-line switches
below. Stop the runner first; pass the same `-ConfigurationPath` if you use a
custom file. Tenant evidence is sent only by an explicitly requested analysis,
not by loading or saving settings.

### Configuration file / command line

You can still configure the file directly. For a new configuration, copy the
example (do not overwrite an existing configured file):

```powershell
Copy-Item .\perception.config.example.json .\perception.config.json
```

Set `model.endpoint` to your complete Azure Responses URL (ending in
`/responses`) and `model.deployment` to your actual deployment name. Use
`model.apiFormat: "chat"` with a complete `/chat/completions` URL for supported
chat deployments. Use `model.tenantId` if the model resource is in a different
approved tenant. `model.tokenResource` is normally
`https://cognitiveservices.azure.com`; approved Foundry connections may use
`https://ai.azure.com`. No credentials belong in this JSON.

Use the appropriate model resource role for your deployment (for example
Cognitive Services OpenAI User for Azure OpenAI). Endpoint validation accepts
public Azure resource HTTPS endpoints, not arbitrary hosts or redirects.

```powershell
# Explicit paid model operations against the saved snapshot:
.\Start-App.ps1 -ModelSynthesis
.\Start-App.ps1 -AnalyzeAgentBehavior

# Standalone model synthesis:
.\New-PerceptionSystemicThreatReport.ps1 -UseModel
```

These operations submit retained report sections or agent evidence to your
configured Azure deployment and can incur charges. Agent behavior and systemic
synthesis have distinct evidence selection. Systemic synthesis excludes agent
transcripts and treats intelligence as context rather than tenant observations.
Access tokens stay in process memory; temporary synthesis inputs/results are
removed after use. Model failures reject the new synthesis instead of presenting
a successful-looking fallback. No Council installation is needed.

The systemic model-input budget defaults to 180,000 characters. Oversize inputs
are rejected before model submission, never silently truncated; use a smaller
snapshot or explicitly increase `-MaxModelInputCharacters` within your deployment's
context capacity. Both the launcher and standalone generator accept this option;
the launcher forwards it unchanged to systemic synthesis. For example, only
after confirming sufficient deployment context capacity:

```powershell
.\Start-App.ps1 -ModelSynthesis -MaxModelInputCharacters 450000
```

The size error reports the actual input characters, sessions and source sections.
Character counts are not token counts; include room for system instructions
and model output when assessing context capacity. Raising this guard preserves
all selected evidence; it does not increase the model's context window.
A model proposal with valid citations is still unverified.

## Understand the reports

- **Environment:** collected sessions, agent runs, messages and artifacts.
- **Operational Briefing:** agent-reported findings, conclusions and actions.
- **Freshness / Run Quality:** evidence age, output availability and incomplete runs.
- **Agent Behavior:** descriptive themes and per-agent deviation, not correctness.
- **Systemic Threat Signals:** cross-run correlations and analyst-reviewable
  hypotheses, including counterevidence, alternatives and next checks.
- **Defender Investigations:** exact incident joins and explicit coverage limits.

Repeated runs are not independent confirmation. Article intelligence is not
observed tenant activity. Recommendations are not executed remediation. Session
start times are not event times. An empty result does not establish safety.

Session discovery currently requests up to the first 500 sessions; an upstream
continuation-URL problem can prevent complete historical enumeration. Defender
reports show incomplete collection and support explicit `-SessionId` collection
when IDs are known. Do not describe these reports as all tenant history.

Opening the app preserves existing behavior/model results. `-Refresh` regenerates
snapshot-based views and local-only systemic signals unless `-ModelSynthesis`
is also supplied; a warning explains that distinction. Behavior analysis and
Defender comparisons are only refreshed with their explicit switches.

## Local API and data handling

The listener accepts loopback requests only. Report routes are fixed, not arbitrary
filesystem paths. `/api/workspace` reports availability and setup state without
returning credentials. `/api/investigate` accepts only numeric incident IDs and
starts the constrained incident investigation playbook; this action is not
performed by opening a report. The loopback app is not intended for network or
multi-user hosting.

Do not expose the port through a tunnel or reverse proxy. Secure the local
directory and exports as tenant data. Never redistribute a used working folder:
it can contain generated reports, real configuration or manually supplied tokens.
Share only a newly built, inspected clean source package.
