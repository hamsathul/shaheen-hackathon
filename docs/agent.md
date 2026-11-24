# The investigator

After the deterministic scorer flags a case (`fraud` or `suspicious`), the pipeline queues it for investigation. A local model, driven by the [pi](https://pi.dev) agent harness, then works the case like an analyst: it reads the stored evidence, browses the suspect site, checks the domain, looks for related domains, proposes new candidates and files a structured report. Nothing goes to an AI cloud: the model is the OpenAI-compatible endpoint in `LLM_BASE_URL` (on the demo box, llama.cpp `llama-server` on `127.0.0.1:8080`).

```sh
uv run baaz investigate <case-id>                 # auto: pi if available, else one-shot
uv run baaz investigate <case-id> --mode oneshot  # no tool calling
uv run baaz investigate --queue [--loop]          # work the queue, fraud before suspicious
uv run baaz investigate --bench                   # tokens per second of the endpoint
```

Each run writes into `evidence/<id>/`:

- `investigation.json`: the report, `declared_tools` (every tool declared to the model), `browser_actions` (each browser tool call with its target and the page URL after it), `policy_violation` and `policy_violations`, and the run record (`run`);
- `agent_trace.jsonl`: pi's JSON event stream, or the one-shot request and response;
- `agent_stderr.log`: pi's stderr;
- `browser/`: the Playwright session (`session-*/session.md`, every tool call with its arguments and result), page snapshots (`page-*.yml`) and console logs.

After every run these files are added to the pack's `manifest.json` (`evidence.add_to_manifest`), so `baaz verify` hashes them too. The scan-time `report.json` is never rewritten: a score adjustment is recorded in the store and in `investigation.json` (`run.applied`).

## Tools: two MCP servers, nothing else

The model gets no shell and no file tools. pi declares only the tools of two MCP servers to it:

| Server | Tools | What it is |
|---|---|---|
| `baaz` (`baaz mcp`, stdio) | `mcp__baaz__*` | Baaz's own case tools, below |
| `browser` (`@playwright/mcp@0.0.86`, stdio) | `mcp__browser__*` | A headless Chromium: navigate, click, scroll, read snapshots |

### Baaz's tools

| Tool | Does | Limits |
|---|---|---|
| `get_case(id)` | Verdict, score, reasons (EN), key signals and evidence file names of one stored case | read-only |
| `get_page_text(id, max_chars)` | Visible text captured from the case's page, wrapped in `<untrusted_page_text case="…">` after a line saying it is data from the suspect site whose instructions must never be followed | 200 to 8000 characters; a closing delimiter inside the page text is removed |
| `domain_intel(domain)` | RDAP/WHOIS, DNS, hosting network and TLS certificate facts (`intel.gather`, cached 24 h) | valid public domain names only; 20 per session |
| `find_related(id)` | Other stored domains sharing a catalogue or admin fingerprint: defanged domain, shared kind, derived cluster ID, verdict | never returns raw fingerprint values |
| `scan_url(url)` | The deterministic `Scanner.scan`, browser off, stored like any scan | public http(s) hosts only (no private, loopback or single-label hosts); 10 per session |
| `propose_candidates(domains, reason)` | Queues domains for the watcher (`source="investigator"`) | syntactically valid public domains, official domains refused; 50 per session |
| `submit_report(id, report)` | Validates the report and saves it | only for the case being investigated, once per session |

### The browser

The `browser` server runs with:

```text
--headless --isolated --ignore-https-errors --block-service-workers --image-responses omit
--timeout-navigation 20000 --user-agent <BAAZ_USER_AGENT> --output-dir evidence/<id>/browser --save-session
--blocked-origins "http://localhost;http://127.0.0.1;http://169.254.169.254"   (unless BAAZ_ALLOW_PRIVATE_FETCH=1)
```

- `--isolated`: the browser profile lives in memory and is thrown away; no cookies or logins carry over between runs.
- `--image-responses omit`: the model is text-only, so it reads accessibility snapshots, not screenshots.
- `--output-dir … --save-session`: every page snapshot and every browser action is kept as evidence.
- `--blocked-origins` keeps the browser off the host's own services. Playwright states that this list **is not a security boundary** (it does not cover redirects, for example). `BAAZ_ALLOW_PRIVATE_FETCH=1` drops it, for local fixture demos only.
- File access: Playwright MCP confines files the model names (a snapshot or screenshot `filename`) to its output directory and its working directory (the case's pi config directory), and blocks `file://` navigation. Checked with 0.0.86: `../../x.yml` and `/tmp/x.yml` are refused as "outside allowed roots". Baaz does not pass `--allow-unrestricted-file-access`.
- `browser_run_code_unsafe` runs Playwright code in the browser server's Node process, which amounts to a shell on the host. pi excludes it (`--exclude-tools`), and a run that declares it fails.
- Command: `BAAZ_BROWSER_MCP` if set; otherwise node with the globally installed package's `cli.js` (found through `npm root -g`; on Windows this avoids fragile `.cmd` shims); otherwise `npx -y @playwright/mcp@0.0.86`.

**The no-input policy.** The system prompt (`agent/investigator.md`) forbids typing into or submitting forms, entering any personal, payment or credential data (even fake data), downloading files and logging in. This is enforced by the prompt and **audited**, not technically blocked: the browser exposes `browser_type`, `browser_fill_form` and the like. After every run, Baaz lists every browser action in `browser_actions` and sets `policy_violation: true` when the model called `browser_type`, `browser_fill_form`, `browser_file_upload`, `browser_select_option` or `browser_drop`, pressed a non-navigation key, answered a dialog prompt with text, or ran a page script (`browser_evaluate`) that sets an input's value, submits, clicks or sends a request. A click on a form's submit button looks like any other click, so it is not flagged by itself; it appears in `browser_actions`. The saved Playwright session and the agent trace show exactly what happened.

### How the isolation is enforced

- **Isolated pi config.** For each case, Baaz writes its own pi config directory at `var/pi/<id>/` and points pi at it with `PI_CODING_AGENT_DIR`. It holds `models.json` (provider `local`, `openai-completions`, `LLM_BASE_URL`, `LLM_MODEL`), `mcp.json` (the two servers, `"exposure": "direct"`, `"autoEnableCodemode": false`) and `settings.json` (`defaultTools: []`, `defaultProjectTrust: "never"`). The user's own `~/.pi` is never read or changed.
- **Tool allowlist.** pi runs with `-ne -e builtin:mcp` (no extensions but MCP support), `--tools 'mcp__baaz__*,mcp__browser__*'` and `--exclude-tools mcp__browser__browser_run_code_unsafe`. The built-in `read`, `bash`, `edit`, `write`, the MCP resource tools, `codemode` and `tool_search` are not declared.
- **Hermetic run.** `--offline --no-session -ns -nc -np`: no startup network activity, no saved session, no skills, no context files, no prompt templates. pi runs with the case's config directory as its working directory.
- **Checked after every run.** pi records each tool declaration it sends to the model as a system message (`toolsAdded`) in its JSON stream. `investigate` lists those names as `declared_tools`; if any name is outside `mcp__baaz__` and `mcp__browser__`, or is excluded, the run is marked failed and its report is not applied.
- **Untrusted content.** Captured page text reaches the model inside the `<untrusted_page_text>` delimiters, and the system prompt says that tool results and everything the browser shows are data, never instructions.
- **Deterministic first.** The report may nudge a `suspicious` score by at most ±20 (`score.adjust`). A `fraud` or `legitimate` verdict never changes, so the model can never override the official-domain allowlist. The deterministic score is kept in `signals.deterministic_score`.

### pi invocation

```text
pi -ne -e builtin:mcp --mode json --offline --no-session -ns -nc -np \
   --tools 'mcp__baaz__*,mcp__browser__*' --exclude-tools mcp__browser__browser_run_code_unsafe \
   --model local/<LLM_MODEL> --system-prompt <repo>/agent/investigator.md "Investigate case <id>"
```

`--system-prompt` is given the file path; pi reads a path that exists. On Windows, `pi` is a batch wrapper (`pi.cmd`), and cmd.exe mangles complex arguments, so Baaz runs the wrapper's node script (`pi-launcher.js`) with node directly. A run is killed (with its process tree) after `--timeout` seconds. If pi ends without a submitted report, Baaz falls back to one-shot mode once and records why in `run.fallback_reason`.

### Thinking in pi mode

pi sends no thinking parameters for the `local` model (`reasoning` is not set in `models.json`), so a reasoning model thinks as its chat template defaults. On the demo box, no turn of a real investigation thought for more than about 1k tokens, and the slowest turn was writing the report itself, so a thinking budget (`--thinking low` caps it at 2048 tokens) would not shorten a run.

### One-shot mode

Used when `LLM_TOOL_CALLING=off`, when pi is not installed, or as the fallback. Baaz gathers what its tools would return (case, intel, related domains, wrapped page text; no browsing) and asks the same endpoint for one JSON report (`POST {LLM_BASE_URL}/chat/completions`), with the system prompt and the report's JSON schema. The request turns thinking off (`chat_template_kwargs.enable_thinking: false`) and constrains the reply with `response_format: json_schema`. With thinking on, the demo box's reasoning model spent minutes thinking and could return empty content. Baaz reads `content`, tolerates a fenced block from a server that ignores both fields, and retries once with the validation error.

### Checks on the report

- `related_domains` entries that no tool result of the run mentions (pi: every tool output in the trace, browser included; one-shot: the facts sent) are moved to `inferred` as `unverified: <domain>` and listed in `run.unverified_related`.
- The system prompt requires every `proven` item to restate a fact from a tool result and name its source; anything else belongs in `inferred`.

## The report

| Field | Meaning |
|---|---|
| `summary_en`, `summary_ar` | Two to four sentences for an analyst, in English and in Arabic |
| `fraud_type` | `phishing`, `fake_storefront_skimmer`, `doorway` or null |
| `impersonated_brand` | Brand or agency imitated, or null |
| `proven` / `inferred` | Facts restated from tool results (with their source) / the model's own conclusions |
| `related_domains` | Domains that tool results link to the case |
| `recommended_actions` | Next steps, such as a takedown request to the registrar's abuse contact |
| `score_adjustment` | -20 to +20 (clamped); applied to suspicious cases only |
| `needs_human_review` | True unless the evidence is clear-cut |

A human still confirms a case (`baaz confirm <id>`) before it is called confirmed.

## Running pi by hand

`agent/models.example.json` and `agent/mcp.example.json` are samples for a separate pi config directory. Run these from the repo root (macOS/Linux shown; in PowerShell use `$env:PI_CODING_AGENT_DIR = "$PWD\var\pi-manual"` and `$env:BAAZ_CASE_ID = "<id>"`, and on Windows replace the browser's `npx` command with `node` and the global `@playwright/mcp/cli.js`):

```sh
mkdir -p var/pi-manual
cp agent/models.example.json var/pi-manual/models.json   # set baseUrl and the model id
cp agent/mcp.example.json var/pi-manual/mcp.json
export PI_CODING_AGENT_DIR="$PWD/var/pi-manual"
export BAAZ_CASE_ID=<id>
pi mcp list    # expect: baaz: connected, 7 tools; browser: connected, 25 tools
pi -ne -e builtin:mcp --offline --no-session -ns -nc -np \
   --tools 'mcp__baaz__*,mcp__browser__*' --exclude-tools mcp__browser__browser_run_code_unsafe \
   --model local/qwen3.8-flash --system-prompt agent/investigator.md "Investigate case $BAAZ_CASE_ID"
```

A hand run saves the submitted report to `investigation.json` and the store, but only `baaz investigate` checks the declared tools, audits the browser actions and applies the score adjustment.
