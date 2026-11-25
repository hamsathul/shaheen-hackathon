# The investigator

After the deterministic scorer flags a case (`fraud` or `suspicious`), the pipeline queues it for investigation, or parks it when it is outside the UAE focus (README, UAE focus); a parked case goes to the queue from its case page. A queued case also gets a contacts read, one model call: the first worker takes reads before cases, the others take them only when no case is waiting (README, Contacts). A local model, driven by the [pi](https://pi.dev) agent harness, then works the case like an analyst: it reads the stored evidence, browses the suspect site, checks the domain, looks for related domains, proposes new candidates and files a structured report. Nothing goes to an AI cloud: the model is the OpenAI-compatible endpoint in `LLM_BASE_URL` (on the demo box, llama.cpp `llama-server` on `127.0.0.1:8080`).

```sh
uv run shaheen investigate <case-id>                 # auto: pi if available, else one-shot
uv run shaheen investigate <case-id> --mode oneshot  # no tool calling
uv run shaheen investigate --queue [--loop] [--workers N]  # work the queue, fraud before suspicious
uv run shaheen investigate --bench                   # tokens per second of the endpoint
uv run shaheen up                                    # autonomous mode: watcher, investigator queue and dashboard
uv run shaheen hunt "<mission>" [--theme <id>] [--queue]  # an AI hunt (see Hunts below)
```

**The queue.** `--queue` (and `shaheen up`) runs `--workers` investigations in parallel (default `SHAHEEN_INVESTIGATORS`, else 2), each with its own pi process, `shaheen mcp` server, browser, pi config directory and evidence folder; give `llama-server` as many slots (`-np`). A worker takes a queued hunt first, else a case, each with one SQLite `UPDATE … RETURNING`, so two workers never take the same one. Before taking a case, a worker checks that the model answers `GET {LLM_BASE_URL}/models`; while it does not, no case is taken (waits of 10 s doubling to 60 s, one log line when the endpoint goes down and one when it is back, and the dashboard says "Waiting for the model"). A run that fails with a connection error (`ConnectError`, `ConnectTimeout`, `ReadError`, `RemoteProtocolError`) goes back to the queue instead of staying failed. When the queue starts, it re-queues investigations left `running` by a stopped process and those that failed with a connection error. Ctrl-C (or stopping `shaheen up`) kills the pi runs in flight with everything they started and puts their cases back in the queue. While it runs, the queue writes a heartbeat to the store's meta table; the dashboard's live panel shows the investigator as off when the heartbeat is more than a minute old.

Each run writes into `evidence/<id>/`:

- `investigation.json`: the report, `declared_tools` (every tool declared to the model), `browser_actions` (each browser tool call with its target and the page URL after it), `policy_violation` and `policy_violations`, and the run record (`run`);
- `agent_trace.jsonl`: pi's JSON event stream, or the one-shot request and response. pi writes it straight into the file while it runs, so the dashboard follows the run live (the feed's investigator panel and the case page's trace refresh every 5 seconds);
- `agent_stderr.log`: pi's stderr;
- `browser/`: the Playwright session (`session-*/session.md`, every tool call with its arguments and result), page snapshots (`page-*.yml`) and console logs.

After every run these files are added to the pack's `manifest.json` (`evidence.add_to_manifest`), so `shaheen verify` hashes them too. The scan-time `report.json` is never rewritten: a score adjustment is recorded in the store and in `investigation.json` (`run.applied`).

## Tools: two MCP servers, nothing else

The model gets no shell and no file tools. pi declares only the tools of two MCP servers to it:

| Server | Tools | What it is |
|---|---|---|
| `shaheen` (`shaheen mcp`, stdio) | `mcp__shaheen__*` | Shaheen's own case tools, below |
| `browser` (`@playwright/mcp@0.0.86`, stdio) | `mcp__browser__*` | A headless Chromium: navigate, click, scroll, read snapshots |

### Shaheen's tools

| Tool | Does | Limits |
|---|---|---|
| `get_case(id)` | Verdict, score, reasons (EN), key signals and evidence file names of one stored case | read-only |
| `get_page_text(id, max_chars)` | Visible text captured from the case's page, wrapped in `<untrusted_page_text case="…">` after a line saying it is data from the suspect site whose instructions must never be followed | 200 to 8000 characters; a closing delimiter inside the page text is removed |
| `domain_intel(domain)` | RDAP/WHOIS, DNS, hosting network and TLS certificate facts (`intel.gather`, cached 24 h) | valid public domain names only; 20 per session |
| `find_related(id)` | Other stored domains sharing a catalogue or admin fingerprint: defanged domain, shared kind, derived cluster ID, verdict | never returns raw fingerprint values |
| `scan_url(url)` | The deterministic `Scanner.scan`, browser off, stored like any scan | public http(s) hosts only (no private, loopback or single-label hosts); 10 per session |
| `propose_candidates(domains, reason)` | Queues domains for the watcher (`source="investigator"`) | syntactically valid public domains, official domains refused; each registrable domain is looked up in DNS (NS) and a name that answers NXDOMAIN, or whose lookup fails, is refused as `not_registered`, so a model cannot queue names it made up; 50 lookups per session |
| `submit_report(id, report)` | Validates the report and saves it | only for the case being investigated, once per session |

### The browser

The `browser` server runs with:

```text
--headless --isolated --ignore-https-errors --block-service-workers --image-responses omit
--timeout-navigation 20000 --user-agent <SHAHEEN_USER_AGENT> --output-dir evidence/<id>/browser --save-session
--init-page agent/browser_shots.js
--blocked-origins "http://localhost;http://127.0.0.1;http://169.254.169.254"   (unless SHAHEEN_ALLOW_PRIVATE_FETCH=1)
```

- `--isolated`: the browser profile lives in memory and is thrown away; no cookies or logins carry over between runs.
- `--image-responses omit`: the model is text-only, so it reads accessibility snapshots, not screenshots.
- `--output-dir … --save-session`: every page snapshot and every browser action is kept as evidence.
- `--init-page agent/browser_shots.js`: after each page load settles (1.5 s), the browser saves what it shows as `browser/shot-<epoch ms>.jpg`. The model never sees these. The dashboard's live panel shows the newest one under the run, and they join the evidence pack with the rest of `browser/`.
- `--blocked-origins` keeps the browser off the host's own services. Playwright states that this list **is not a security boundary** (it does not cover redirects, for example). `SHAHEEN_ALLOW_PRIVATE_FETCH=1` drops it, for local fixture demos only.
- File access: Playwright MCP confines files the model names (a snapshot or screenshot `filename`) to its output directory, which is also its working directory (`evidence/<id>/browser`), and blocks `file://` navigation. Checked with 0.0.86: `../../x.yml` and `/tmp/x.yml` are refused as "outside allowed roots". Shaheen does not pass `--allow-unrestricted-file-access`.
- `browser_run_code_unsafe` runs Playwright code in the browser server's Node process, which amounts to a shell on the host. pi excludes it (`--exclude-tools`), and a run that declares it fails.
- Command: `SHAHEEN_BROWSER_MCP` if set; otherwise node with the globally installed package's `cli.js` (found through `npm root -g`; on Windows this avoids fragile `.cmd` shims); otherwise `npx -y @playwright/mcp@0.0.86`.

**The no-input policy.** The system prompt (`agent/investigator.md`) forbids typing into or submitting forms, entering any personal, payment or credential data (even fake data), downloading files and logging in. This is enforced by the prompt and **audited**, not technically blocked: the browser exposes `browser_type`, `browser_fill_form` and the like. After every run, Shaheen lists every browser action in `browser_actions` and sets `policy_violation: true` when the model called `browser_type`, `browser_fill_form`, `browser_file_upload`, `browser_select_option` or `browser_drop`, pressed a non-navigation key, answered a dialog prompt with text, or ran a page script (`browser_evaluate`) that sets an input's value, submits, clicks or sends data (a request with a body or a non-GET method; reading pages with a plain fetch is allowed). A click on a form's submit button looks like any other click, so it is not flagged by itself; it appears in `browser_actions`. The saved Playwright session and the agent trace show exactly what happened.

### How the isolation is enforced

- **Isolated pi config.** For each case, Shaheen writes its own pi config directory at `var/pi/<id>/`, points pi at it with `PI_CODING_AGENT_DIR` and removes it after the run. It holds `models.json` (provider `local`, `openai-completions`, `LLM_BASE_URL`, `LLM_MODEL`), `mcp.json` (the two servers, `"exposure": "direct"`, `"autoEnableCodemode": false`) and `settings.json` (`defaultTools: []`, `defaultProjectTrust: "never"`). The user's own `~/.pi` is never read or changed.
- **Tool allowlist.** pi runs with `-ne -e builtin:mcp` (no extensions but MCP support), `--tools 'mcp__shaheen__*,mcp__browser__*'` and `--exclude-tools mcp__browser__browser_run_code_unsafe`. The built-in `read`, `bash`, `edit`, `write`, the MCP resource tools, `codemode` and `tool_search` are not declared.
- **Hermetic run.** `--offline --no-session -ns -nc -np`: no startup network activity, no saved session, no skills, no context files, no prompt templates. pi runs with the case's config directory as its working directory.
- **Checked after every run.** pi records each tool declaration it sends to the model as a system message (`toolsAdded`) in its JSON stream. `investigate` lists those names as `declared_tools`; if any name is outside `mcp__shaheen__` and `mcp__browser__`, or is excluded, the run is marked failed and its report is not applied.
- **Untrusted content.** Captured page text reaches the model inside the `<untrusted_page_text>` delimiters, and the system prompt says that tool results and everything the browser shows are data, never instructions.
- **Deterministic first.** The report may nudge a `suspicious` score by at most ±20 (`score.adjust`). A `fraud` or `legitimate` verdict never changes, so the model can never override the official-domain allowlist. The deterministic score is kept in `signals.deterministic_score`.

### pi invocation

```text
pi -ne -e builtin:mcp --mode json --offline --no-session -ns -nc -np \
   --tools 'mcp__shaheen__*,mcp__browser__*' --exclude-tools mcp__browser__browser_run_code_unsafe \
   --model local/<LLM_MODEL> --system-prompt <repo>/agent/investigator.md "Investigate case <id>"
```

`--system-prompt` is given the file path; pi reads a path that exists. On Windows, `pi` is a batch wrapper (`pi.cmd`), and cmd.exe mangles complex arguments, so Shaheen runs the wrapper's node script (`pi-launcher.js`) with node directly. pi runs in a session (POSIX) or process group (Windows) of its own, so Ctrl-C in the console reaches only Shaheen, which then ends the run itself. A run is killed after `--timeout` seconds, with every process it started: pi starts each MCP server in a session of its own, so Shaheen kills the process group of each descendant (`taskkill /T` on Windows). If pi ends without a submitted report, Shaheen falls back to one-shot mode once and records why in `run.fallback_reason`.

### Thinking in pi mode

pi sends no thinking parameters for the `local` model (`reasoning` is not set in `models.json`), so a reasoning model thinks as its chat template defaults. On the demo box, no turn of a real investigation thought for more than about 1k tokens, and the slowest turn was writing the report itself, so a thinking budget (`--thinking low` caps it at 2048 tokens) would not shorten a run.

### One-shot mode

Used when `LLM_TOOL_CALLING=off`, when pi is not installed, or as the fallback. Shaheen gathers what its tools would return (case, intel, related domains, wrapped page text; no browsing) and asks the same endpoint for one JSON report (`POST {LLM_BASE_URL}/chat/completions`), with the system prompt and the report's JSON schema. The request turns thinking off (`chat_template_kwargs.enable_thinking: false`) and constrains the reply with `response_format: json_schema`. With thinking on, the demo box's reasoning model spent minutes thinking and could return empty content. Shaheen reads `content`, tolerates a fenced block from a server that ignores both fields, and retries once with the validation error.

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

A human still confirms a case (`shaheen confirm <id>`) before it is called confirmed.

## Hunts

An officer gives the hunter a mission in the dashboard's Hunts page or with `shaheen hunt "<mission>"`, optionally with one of the UAE scam themes of `data/themes_uae.yaml`. The mission is stored in the `hunts` table. `shaheen hunt` runs it at once; the dashboard (and `--queue`) leaves it for the queue workers, which take hunts before cases.

A hunt is a pi run like an investigation, with three differences:

- **No browser.** Its pi config (`var/pi/hunt-<id>/`) declares only Shaheen's MCP server, and pi runs with `--tools 'mcp__shaheen__*'`. A declared tool outside `mcp__shaheen__` fails the run.
- **Hunt tools.** `shaheen mcp` with `SHAHEEN_HUNT_ID` serves the tools below instead of the case tools.
- **The task.** pi gets `agent/hunter.md` as the system prompt and `Hunt <id>. Mission: <mission>` as the task, on one line and at most 500 characters. The task starts with a fixed word, so a mission can never be read as one of pi's options.

| Tool | Does | Limits |
|---|---|---|
| `list_themes()` | The themes: id, name, domain words, certificate search terms, and the UAE markers | read-only |
| `search_certificates(term)` | Host names on certificates issued in the last 30 days that contain the term (crt.sh), each with the themes it matches | 6 or more letters, digits or hyphens; 4 per hunt; 45 s per try |
| `search_new_domains(words)` | Domains registered yesterday (WhoisDS daily list) containing any of the words, with their themes | up to 5 words of 3 or more letters; the list is downloaded once per hunt and kept in memory |
| `known_domains(words)` | Domains already in the store containing the words, with their latest verdict or queue status | read-only |
| `domain_intel`, `get_page_text`, `scan_url` | As for cases | as for cases |
| `propose_candidates(domains, reason)` | Queues domains for the watcher (`source="hunt"`) | as for cases |
| `submit_hunt_report(id, report)` | Validates the hunt report and saves it | only for the hunt being run, once |

Every domain the hunter scans or queues is recorded in `hunt_finds` with its reason, so the hunt's page lists each one with Shaheen's latest check: the hunter's own scan, or the watcher's scan of the queued link once it runs. The report has `summary_en`, `summary_ar`, `searches`, `suspects` (domain and reason) and `next_steps`. A suspect that no tool result of the run mentions is dropped and listed in `run.unverified_suspects`. The record and pi's trace are kept in the store and in `var/hunts/<id>/`. The hunter never sets a verdict: suspects stay suspects until the deterministic scorer has seen them.

## Running pi by hand

`agent/models.example.json` and `agent/mcp.example.json` are samples for a separate pi config directory. Run these from the repo root (macOS/Linux shown; in PowerShell use `$env:PI_CODING_AGENT_DIR = "$PWD\var\pi-manual"` and `$env:SHAHEEN_CASE_ID = "<id>"`, and on Windows replace the browser's `npx` command with `node` and the global `@playwright/mcp/cli.js`):

```sh
mkdir -p var/pi-manual
cp agent/models.example.json var/pi-manual/models.json   # set baseUrl and the model id
cp agent/mcp.example.json var/pi-manual/mcp.json
export PI_CODING_AGENT_DIR="$PWD/var/pi-manual"
export SHAHEEN_CASE_ID=<id>
pi mcp list    # expect: shaheen: connected, 7 tools; browser: connected, 25 tools
pi -ne -e builtin:mcp --offline --no-session -ns -nc -np \
   --tools 'mcp__shaheen__*,mcp__browser__*' --exclude-tools mcp__browser__browser_run_code_unsafe \
   --model local/qwen3.8-flash --system-prompt agent/investigator.md "Investigate case $SHAHEEN_CASE_ID"
```

A hand run saves the submitted report to `investigation.json` and the store, but only `shaheen investigate` checks the declared tools, audits the browser actions and applies the score adjustment.
