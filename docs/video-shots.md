# One-minute proof video: shot list

Recorded on the demo box (A10A, Windows 11) in `cmd` from the repo folder, with the browser at
`http://127.0.0.1:8000/`. Start the model server before recording. `uv run baaz demo --watch` loads the demo
cases (a case already loaded is skipped, so every take looks the same), then serves the dashboard with the
watcher running in the background.

The demo cases in `demo/cases/` are one real scan of the official ADCB site plus synthetic captures of invented
`.test` domains built from hand-written pages (no real scam page is stored in the repo); the one AI investigation
shipped with them is illustrative. Real-world results are in `eval/results/`.

| # | Time | Action (exact command or click) | Must be visible |
|---|---|---|---|
| 1 | 0:00-0:08 | Show the desktop: Task Manager on the Performance tab next to the `llama-server` console. | GPU and memory graphs under load; the console line naming the model `qwen3.8-flash` and `127.0.0.1:8080`. No cloud API anywhere. |
| 2 | 0:08-0:20 | `uv run baaz demo --watch`, then open `http://127.0.0.1:8000/`. Wait for one refresh. | Header "Baaz باز"; "Running since" with uptime; the counters (candidates seen, scanned, flagged, AI-investigated, analyst-confirmed) going up; new rows flashing in the feed with red, amber and green verdict badges and defanged domains. |
| 3 | 0:20-0:35 | Click the `bose-uae-outlet[.]test` row. Scroll slowly from the verdict to the trace. Click "العربية" in the header, then back. | FRAUD 100; English and Arabic reasons side by side with their evidence pointers (`storefront.json#payment_methods`); the screenshot; "AI investigation" with mode `pi`, proven vs inferred; the tool-call trace (`get_case`, `get_page_text`, `domain_intel`, `find_related`, `browser_navigate`, `submit_report`); the whole page flipping to Arabic, right to left. |
| 4 | 0:35-0:47 | Pull the network cable (or switch on airplane mode). In `cmd`: `uv run baaz scan --from-capture demo\cases\storefront-skimmer` | The same verdict, score and reasons as the dashboard, printed with no network; the new evidence folder path. |
| 5 | 0:47-1:00 | Back in the browser on the `adcb-secure-verify[.]test` case: type an analyst name, click "Confirm as fraud", click "Download evidence pack (.zip)". In `cmd`: `uv run baaz verify <case id>` | "Case confirmed"; the takedown request with the registrar and hosting abuse contacts; the zip download; `OK ... every file matches manifest.json` with the manifest SHA-256. |
