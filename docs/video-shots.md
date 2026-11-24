# One-minute proof video: shot list

Recorded on the demo box (A10A, Windows 11) in `cmd` from the repo folder, with the browser at
`http://127.0.0.1:8000/`. Everything runs from one command, `uv run baaz up`: the watcher (collectors and scanning
workers), the AI investigator (two parallel pi runs against the local model) and the dashboard, in one process.
Nothing is scripted: the feed, the counters and the investigator panel show what Baaz is doing at that moment.

## Before recording

1. Start the model server (llama.cpp `llama-server`, model `qwen3.8-flash` on `127.0.0.1:8080`, `-np 2` so the two
   investigators each get a slot). Check `.env`: `LLM_BASE_URL=http://127.0.0.1:8080/v1`, `LLM_MODEL=qwen3.8-flash`.
2. Stop any separate `baaz watch`, `baaz investigate --queue` or `baaz dashboard` on the box (`taskkill /PID <pid>`), so
   port 8000 is free and only one investigator works the queue.
3. Use a fresh store so the counters visibly start from zero:

   ```bat
   set BAAZ_DB=var\video.db
   uv run baaz up
   ```

   `BAAZ_DB` only names the database file; evidence still goes to `evidence\`. Delete `var\video.db` (and its
   `-wal` and `-shm` files) to start again from zero.
4. The first collector round sweeps likely storefront names first (about a minute; it usually finds live skimmer
   stores), then the lookalike domains (about ten minutes on a fresh store). Scans start as soon as the first
   candidate is queued. An investigation takes 4 to 5 minutes, so let `baaz up` run for about 15 minutes before
   recording shots 3 to 7; record shot 2 right after starting it, while the counters are still near zero.
5. For the Maps shot, put both Google keys in `.env` (`GOOGLE_MAPS_API_KEY` for the searches,
   `GOOGLE_MAPS_BROWSER_KEY` for the map; see the README) and check that the "Google Maps watch" panel under the
   investigator shows the map. On a fresh store the first Maps round runs by itself a minute or two after `baaz up`
   starts. "Search Maps now" is allowed again 10 minutes after a round ends; the panel shows "Next allowed at" until
   then.
6. If no flagged case has turned up yet, queue an invented lookalike: `uv run baaz enqueue
   https://adcb-secure-verify.test/login` scores suspicious from its address alone and is investigated within seconds
   (the site does not exist, so the agent's browser visit fails; a live skimmer from the sweep makes a better shot).

## Shots

| # | Time | Action (exact command or click) | Must be visible |
|---|---|---|---|
| 1 | 0:00-0:05 | Show the desktop: Task Manager on the Performance tab next to the `llama-server` console. | GPU and memory graphs under load; the console naming the model `qwen3.8-flash` on `127.0.0.1:8080`. No cloud model anywhere. |
| 2 | 0:05-0:13 | In `cmd`: `set BAAZ_DB=var\video.db`, then `uv run baaz up`. Open `http://127.0.0.1:8000/`. | The console lines prefixed `up`, `watch`, `agent-1`/`agent-2` and `web` ("investigator: 2 workers, pi mode, model qwen3.8-flash at http://127.0.0.1:8080/v1"); in the browser, "Running since" and the counters (candidates seen, scanned, flagged, AI-investigated, analyst-confirmed) counting up from zero, new rows flashing into the feed with solid red (fraud), red-outlined (suspicious) and green (legitimate) badges and defanged domains. |
| 3 | 0:13-0:23 | (About 15 minutes later.) Stay on the feed; let one 5-second refresh happen. | The "AI investigator" panel: state "Investigating", the local model's name, one block per running investigation (verdict badge, score, defanged domain, elapsed time ticking, tool-call count) with its tool calls appearing, newest last: `get_case`, `get_page_text`, `domain_intel`, then `browser_navigate hxxps://…[.]com/…`, `browser_snapshot`, `browser_click`; the queue (fraud / suspicious); "Recently finished" with fraud type and the first sentence of each report; the "AI" tag on investigated feed rows. |
| 4 | 0:23-0:35 | Scroll down to "Google Maps watch" under the investigator and click "Search Maps now". Let two or three searches arrive. | The state "Searching" with the query under way; the map moving to each search about 6 seconds apart, with solid red squares for leads, green outlines for the brand's own listings and small grey squares for other businesses; beside it the log filling in, the current search highlighted, its listing and lead counts, lead names linking to the Maps leads page and their websites defanged; Arabic queries in Arabic script. |
| 5 | 0:35-0:44 | Click a domain under "Recently finished". Scroll slowly from the verdict to the trace. | The case page: verdict and score; reasons in English and Arabic with their evidence pointers; "AI investigation" with mode `pi`, the English and Arabic summaries, "Proven (from evidence)" vs "Inferred (needs a human)", related domains, recommended actions; the browser audit; the tool-call trace with each call's arguments and result. (Opening a case that is still under investigation shows its trace growing every 5 seconds, then the report appears by itself.) |
| 6 | 0:44-0:48 | Click "العربية" in the header, then back to the feed. | The whole dashboard right to left in Arabic, the live panel included, then back. |
| 7 | 0:48-0:55 | On a fraud case: type an analyst name, click "Confirm as fraud", click "Download evidence pack (.zip)". In a second `cmd` window (same folder): `uv run baaz verify <case id>` | "Case confirmed"; the takedown request with the registrar and hosting abuse contacts; the zip download; `OK ... every file matches manifest.json` with the manifest SHA-256 (the investigation's report, trace and browser session are in the manifest too). |
| 8 | 0:55-1:00 | Pull the network cable (or switch on airplane mode). In the second `cmd` window: `uv run baaz scan --from-capture demo\cases\storefront-skimmer` | The same verdict, score and reasons, printed with no network; the new evidence folder path. |

Cut-ins, if a longer cut is allowed (each about 5 seconds):

| Action | Must be visible |
|---|---|
| Click "Simple" in the header. | Four big numbers in plain words and the "Likely scams" list, each with the brand and one sentence in English and Arabic; no scores, tool calls or hashes. Click "Analyst" to return. |
| Click "Statistics". | Scans per hour by verdict, the most impersonated brands, which collector found them (Google Maps among them), fraud types and the investigator's median time and tool calls, all from the live store. |
| Click "Reports", then "Last 7 days". | The evidence reports library with its filters, then the threat summary: new fraud sites with the AI's one-liners, linked clusters, takedowns grouped by registrar, Maps leads; "Print / save as PDF" gives an A4 report. `uv run baaz summary --period 7d` writes the same report as one file. |

Stop with Ctrl-C in the `baaz up` window: it ends the investigations in flight (their cases go back to the queue),
lets the scans in flight finish and exits.

## Notes

- Shot 8 re-analyses a saved capture offline. The capture folders in `demo/cases/` are one real scan of the
  official ADCB site plus synthetic captures of invented `.test` domains built from hand-written pages (no real
  scam page is stored in the repo). `uv run baaz demo --watch` loads them into the store and serves the dashboard,
  for a take that must look the same every time; the investigation shipped with them is illustrative.
- If the model server is restarted while `baaz up` runs, the panel shows "Waiting for the model" and no case is
  taken until the model answers again; nothing is marked failed.
- Real-world detection results are in `eval/results/`.
