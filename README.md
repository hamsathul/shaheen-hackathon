# Shaheen شاهين

**Shaheen is a 24/7 scam-site hunter for UAE brands. It scores any link with reasons in English and Arabic, watches for new fake sites around the clock, and has a local AI model investigate what it flags, so no case data leaves the building.**

Built for the ScamShield AI Hackathon (42 Abu Dhabi with Abu Dhabi Police). Shaheen (شاهين) is Arabic for the peregrine falcon.

![Live feed](docs/screenshots/feed.png)

## The problem

Scam sites reach UAE residents through the same channels as real brands: search results, sponsored ads and SMS links. A victim searches "pay traffic fine abu dhabi" or "bose uae", clicks a top result and types card details into a page that looks right. These sites are registered in bulk, live for days, hide from crawlers and move to new domains when reported. By the time an analyst sees one, ten more exist.

Shaheen grew out of a real case. A number-one Google result for "bose uae" led to a fake store that took card numbers in its own checkout form. Manual work traced it to a network of 93 fake storefronts across 11 brands, 14 of them aimed at the UAE and the Gulf ([case study](docs/case-study.md)). Shaheen automates that hunt, and those 93 stores are its first benchmark.

## What Shaheen does

Three roles share one pipeline, `scan(url)`.

| Role | Command | What it does |
|---|---|---|
| **Scorer** | `shaheen scan <url>` | Scores a link 0 to 100 with reasons in English and Arabic and writes a hashed evidence pack. Deterministic; no AI involved. |
| **Watcher** | `shaheen watch` | Runs 24/7. Five collectors (brand lookalikes, Certificate Transparency, newly registered domains, a brand × country storefront sweep, Google Maps listings) feed candidates to the scorer. |
| **Investigator** | `shaheen investigate` | A local model, driven by the [pi](https://pi.dev) agent harness, works each flagged case with Shaheen's read-only case tools and a headless browser, then files a report that separates proven facts from inferences. |

Officers and analysts work the results in the dashboard (`shaheen dashboard`), in English or Arabic. It opens in Simple mode; "Analyst" in the header shows the full detail:

- **Simple mode (the default):** for officers who are not analysts. Big plain numbers, then the likely scams, each with the brand it pretends to be and one sentence in English and Arabic; no scores, tool calls or hashes.
- **Live feed:** counters, the AI investigator panel with each running investigation's tool calls as they happen, the Google Maps watch with its map, and every scan as it is scored.
- **Case view:** verdict, reasons in both languages with their evidence pointers, the page screenshot, the AI investigation (proven facts apart from inferences) and its tool-call trace, confirm, takedown request and evidence download.
- **Statistics:** a top row of headline figures (links checked, distinct domains, each verdict, brands targeted, scans and fraud in the last hour and day, operator links between sites, the AI investigator's queue and median run, Google Maps searches and leads), then scans per hour by verdict, the most impersonated brands, which collector found them and fraud types, all computed from the store.
- **Reports:** every case's evidence report with filters, and a threat summary for the police (today, 24 hours or 7 days) that prints on A4; `shaheen summary` writes the same report as one file.
- **Maps leads:** Google Maps listings that use a brand's name with an off-brand website or a fake helpline number.

`shaheen up` runs all of it in one process: the watcher finds and scores candidates, two investigators work the flagged cases in parallel (fraud first), and the dashboard shows each investigation's tool calls as they happen. If the model goes away, the investigators wait for it and claim nothing; a run cut off by a lost connection goes back in the queue.

### Design rules

- **Deterministic first, AI second.** Weighted signals decide the verdict. The model explains, links cases and proposes new candidates. It may move a `suspicious` score by at most 20 points; it never changes a `fraud` or `legitimate` verdict and never overrides the official-domain allowlist.
- **Always a verdict.** When a page cannot be fetched, Shaheen scores from the URL and domain alone and says so (`fetch_status`).
- **Web content is untrusted.** Page text reaches the model only inside delimiters, as data. The model has no shell and no file access.
- **Non-intrusive.** Shaheen reads public pages and endpoints with unauthenticated GET requests. It never submits a form, enters a credential or probes for weaknesses.
- **A human confirms.** Only an analyst-confirmed case gets a takedown request.

## Screenshots

These are from the live run on the demo box on 2026-11-24. The case and the evidence report are a real fake JBL store aimed at the UAE, and the investigation is the local model working a fake Bose store aimed at Italy.

| Case view: verdict, reasons in English and Arabic, page screenshot | Arabic interface (right to left) |
|---|---|
| ![Case view](docs/screenshots/case.png) | ![Arabic interface](docs/screenshots/case-arabic.png) |

| AI investigation: proven facts apart from inferences | Tool-call trace: Shaheen tools and the browser |
|---|---|
| ![AI investigation](docs/screenshots/investigation.png) | ![Tool-call trace](docs/screenshots/trace.png) |

| Simple mode for officers | Statistics from the live store |
|---|---|
| ![Simple mode](docs/screenshots/simple.png) | ![Statistics](docs/screenshots/stats.png) |

| Google Maps watch: one round of searches in the emirate of Abu Dhabi | Threat summary for the police (last 7 days) |
|---|---|
| ![Google Maps watch](docs/screenshots/maps-watch.png) | ![Threat summary](docs/screenshots/threat-summary.png) |

| Printable evidence report |
|---|
| ![Evidence report](docs/screenshots/evidence-report.png) |

Every suspect address is defanged (`hxxps://example[.]com`) and none is clickable.

## How it works

```text
collectors: lookalikes | CT logs | new domains | storefront sweep        shaheen enqueue <url|file>
                 \                                                      /
                  -> candidate queue (SQLite) <------------------------
                  -> scan(url): resolve -> allowlist -> intel -> render -> page + storefront signals
                                -> score -> reasons (EN/AR) -> evidence pack (SHA-256 manifest)
                  -> fraud / suspicious -> investigation queue (fraud first)
                  -> pi + local model: Shaheen MCP tools + headless browser -> report, new candidates
                  -> dashboard (FastAPI) | CLI JSON | CSV | evidence zip
```

**Resolve.** Follows HTTP, meta-refresh and JavaScript redirects (10 hops) and URL shorteners, and records the chain. It also fetches the page as an Arabic-language mobile visitor, a desktop visitor and a search-engine crawler, to catch sites that show each a different page.

**Allowlist.** 58 brands: 27 UAE government bodies, banks and services, 11 brands seen in the skimmer network, and 20 global brands, each with official domains checked on the organisation's own site (`data/brands_*.yaml`). A link is official only if every hop is official, a government namespace, a shortener or the same brand. Hosting platforms are never allowlisted, and an open redirect blocks the allowlist.

**Intel.** RDAP/WHOIS creation date and registrar, DNS, hosting network and the TLS certificate.

**Render.** Headless Chromium captures the final page, its visible text, forms and a screenshot.

**Storefront.** For WooCommerce sites, the public Store API gives the checkout's payment gateways, the price list and the catalogue. Skimmer stores use private gateways and fake discounts, and share catalogues and administrator accounts across domains.

**Score.** Each signal has a fixed weight. 70 or more is `fraud`, 40 or more is `suspicious`. A skimmer-only payment gateway forces `fraud`. `fraud` also needs evidence from the scam itself (its page, its checkout or a fingerprint shared with known fraud): a lookalike name with a fresh registration but no page to see stops at 69, `suspicious`, and the reasons say so.

| Weight | Signal |
|---:|---|
| +60 | Checkout uses a private payment gateway seen only on card-skimming stores |
| +40 | Lookalike of an official domain: typo, homoglyph, punycode, brand plus extra words, subdomain spoof (+25 for the same name under another ending) |
| +40 | Page sends data to a Telegram bot (a phishing kit's drop box) |
| +35 | Checkout collects card number, expiry and CVV in the site's own form, with no recognised payment processor |
| +30 | Page presents itself as a brand and asks for a password, card, OTP or Emirates ID, off the brand's domains |
| +30 | Domain registered in the last 7 days (+20 within 30 days) |
| +30 | Shares a catalogue or administrator with a known fraud cluster |
| +25 | Brand plus a place name (`bose-uae`, `jbldubai`) |
| +20 | Most sampled products discounted by more than 70% |
| +20 | Bare IP address instead of a domain |
| +15 | Brand name in a non-official domain; doorway page; cloaking; form posting to another domain; generic gateway seen alongside skimmer gateways; `@` in the link |
| +10 | Many subdomain levels; very long link; new TLS certificate; free hosting; abused TLD; urgency wording; deceptive domain words |
| −15 | Domain registered for years |
| −25 | Among the most visited sites on the web (Tranco top 100k) |

Weights and the EN/AR reason text are in `shaheen/score.py` and `shaheen/reasons.py`. Every reason points at the evidence file and field it comes from, such as `storefront.json#payment_methods`.

**Evidence pack.** Each scan writes `evidence/<id>/`: the redirect chain, WHOIS, DNS, certificate, page HTML and text, screenshot, storefront facts, a printable `report.html` and a `manifest.json` with the SHA-256 of every file. `shaheen verify` recomputes the hashes, and `shaheen confirm` refuses a pack that fails.

**Reports.** The dashboard's Reports page lists every case's evidence report, newest first, filtered by verdict, brand, scan date and domain, with links to the case, its `report.html` and its zip. It also opens the threat summary for the police, for today, the last 24 hours or the last 7 days (UAE days), in English or Arabic, printable on A4. The summary covers the links checked and flagged, the new fraud sites with the AI investigator's one-line summary, the brands hit, and the sites that share an administrator account, a product catalogue or a skimmer gateway. It also lists suggested takedowns grouped by registrar, and the Google Maps leads. `shaheen summary` writes the same report as one self-contained HTML file to email.

**Investigator.** For each flagged case, Shaheen writes a private pi configuration that declares only two MCP servers: Shaheen's own case tools (`get_case`, `get_page_text`, `domain_intel`, `find_related`, `scan_url`, `propose_candidates`, `submit_report`) and a headless Playwright browser in a throwaway profile. After the run Shaheen checks the tool list pi actually sent the model, audits every browser action, and adds the trace and browser session to the evidence pack. Details: [docs/agent.md](docs/agent.md).

## Run it

Shaheen runs natively on Windows 11, macOS and Linux with Python 3.11+ and [uv](https://docs.astral.sh/uv/). The demo box is Windows 11 with no Docker.

```sh
git clone <this repo> shaheen
cd shaheen
uv sync
uv run playwright install chromium
copy .env.example .env          # cp on macOS/Linux
```

The scorer, watcher, dashboard and evaluation need nothing else. For the investigator:

1. **A local model** behind an OpenAI-compatible endpoint. On the demo box, llama.cpp (`winget install ggml.llamacpp`):
   ```sh
   llama-server -m <model>.gguf --alias qwen3.8-flash --host 127.0.0.1 --port 8080 -ngl 99 -c 262144 -np 2 --jinja
   ```
   `-np 2` gives the server two slots, one for each parallel investigation (each slot gets half the context). Then set `LLM_BASE_URL=http://127.0.0.1:8080/v1` and `LLM_MODEL=qwen3.8-flash` in `.env`.
2. **pi 1.5** (`powershell -c "irm https://pi.dev/install.ps1 | iex"` on Windows, `curl -fsSL https://pi.dev/install.sh | sh` elsewhere; it needs Node.js 22.19+).
3. **The browser server:** `npm install -g @playwright/mcp@0.0.86`.

Without pi, the investigator falls back to a one-shot report from the same model. Without a model, everything except the investigator still works.

### Commands

```sh
# Everything at once: watcher, 2 investigators and the dashboard (http://127.0.0.1:8000/)
uv run shaheen up
uv run shaheen up --investigators 1 --no-render   # lighter machine

# Score one link (add --json for one machine-readable object, --no-render to skip the browser)
uv run shaheen scan https://example.com/

# Re-run the scoring on a saved evidence folder with no network at all
uv run shaheen scan --from-capture demo/cases/storefront-skimmer

# Score a list (text, one link per line, or CSV with a url column)
uv run shaheen batch links.txt --out results.csv

# Hunt 24/7: collectors plus 4 scanning workers; --once for one round
uv run shaheen watch
uv run shaheen enqueue suspects.txt --source tip-line

# Investigate flagged cases with the local model
uv run shaheen investigate <case-id>
uv run shaheen investigate --queue --loop --workers 2
uv run shaheen investigate --bench          # tokens per second of the model endpoint

# Analyst workflow
uv run shaheen dashboard                    # http://127.0.0.1:8000/
uv run shaheen confirm <case-id> --analyst "Name" --note "..."
uv run shaheen export <case-id>             # evidence zip
uv run shaheen verify <case-id>             # recompute every SHA-256
uv run shaheen summary --period 7d --lang ar   # threat summary as one HTML file in evidence/reports/

# Fixed demo cases plus dashboard (and the watcher with --watch)
uv run shaheen demo
```

`shaheen scan --json` prints one object with the URL, final URL, redirect chain, fetch status, verdict, score, confidence, fraud type, impersonated brand, reasons (code, weight, English, Arabic, evidence pointer), key signals and the evidence path.

On Linux, `docker compose up` runs the watcher and the dashboard (localhost:8000) in containers.

### Google Maps

The Maps collector runs victim-style searches on Google Maps, such as "ADCB customer service", "بنك أبوظبي التجاري خدمة العملاء" and "pay traffic fine Al Ain", and checks each listing that names a watched brand. The searches cover the emirate of Abu Dhabi only (Abu Dhabi city, Al Ain and Al Dhafra), the area Abu Dhabi Police covers: each is restricted to a rectangle around the emirate, and a listing counts only when Google gives Abu Dhabi as its emirate, which drops the corners of Dubai and Al Buraimi the rectangle also touches. A listing whose website is not on the brand's official domains sends that website to the scorer. A listing that presents itself as the brand's helpline with a number that is not one of the brand's verified numbers is kept for an analyst. Both appear on the dashboard's Maps leads page. Neither is a verdict.

It needs a key for Google's Places API (New):

1. In the Google Cloud console, create a project and link a billing account to it.
2. Enable **Places API (New)** for the project.
3. Under APIs & Services > Credentials, create an API key and restrict it to Places API (New).
4. Put the key in `.env` as `GOOGLE_MAPS_API_KEY=...`.

Without a key the watcher logs one line and runs the other collectors. `uv run shaheen watch --once --collectors maps` runs one Maps round and logs each lead.

Each round sends 6 searches, one request each, about 6 seconds apart, and a round runs every 6 hours (`SHAHEEN_MAPS_INTERVAL_HOURS` in `.env`). The searches ask for each listing's website, phone and location, so Google bills them under its "Places API Text Search Enterprise" SKU. That SKU's free usage cap is 1,000 calls a month, then $35.00 per 1,000 calls ([Google Maps Platform pricing](https://developers.google.com/maps/billing-and-pricing/pricing), checked 2026-11-24). The default interval makes at most 24 searches a day, 744 in a 31-day month, which stays inside the free cap. A shorter interval costs more, and so does each press of "Search Maps now" (6 searches).

**The live Maps watch.** Under the AI investigator, the feed shows the Maps searches as they happen: each search's time, query, listing count and lead count, the search under way highlighted, and the lead listings linked to the Maps leads page (their websites defanged, never links). The header shows the last and next round and the searches sent today. "Search Maps now" starts a round at once, at most one every 10 minutes counted from the end of the last round. It continues the rotation, so each press runs new searches, and the watcher scans the websites it queues straight away. The panel is fed by the watcher in the same process, so it is live in `shaheen up` (and `shaheen demo --watch`). A dashboard started on its own with `shaheen dashboard` says so and shows only the last round and today's count. Listing names and locations stay in the memory of the `shaheen up` process and are never written to the database: Google's terms let Shaheen keep place IDs, and coordinates for up to 30 days, but no other listing content. The panel keeps the last round and the search under way.

With a second key the panel draws each search on a Google map: a solid red square for a lead, a green outline for a listing that names the brand with nothing flagged, a small grey square for any other business. The map moves to each search as its answer arrives. Google's terms do not allow Places content on a non-Google map ([Service Specific Terms](https://cloud.google.com/maps-platform/terms/maps-service-terms), section 15.2), so this uses the Maps JavaScript API, the only script Shaheen loads from outside. To create the key:

1. In the same Google Cloud project, enable **Maps JavaScript API**.
2. Under Google Maps Platform > Keys & Credentials, create an API key.
3. Under Application restrictions choose **Websites** and add `http://127.0.0.1:8000/*` and `http://localhost:8000/*` (the dashboard's address; add another if you serve it on another host or port).
4. Under API restrictions choose **Restrict key** and select only **Maps JavaScript API**.
5. Put it in `.env` as `GOOGLE_MAPS_BROWSER_KEY=...`.

This key is sent to the browser, which is why it is separate from `GOOGLE_MAPS_API_KEY`, which never leaves the server. Without it, or without a network, the panel shows the search log alone with one line saying why. Each load of the feed page is one "Dynamic Maps" map load (the 5-second refresh reuses the map). That SKU's free usage cap is 10,000 loads a month, then $7.00 per 1,000 ([Google Maps Platform pricing](https://developers.google.com/maps/billing-and-pricing/pricing), checked 2026-11-24).

## Evaluation

All numbers come from one command, run on the demo box on 2026-11-24 with the scoring code in this commit:

```sh
uv run shaheen eval eval/phish_openphish.txt eval/ground_truth_skimmers.txt eval/legit_woocommerce.txt eval/legit_top_sites.txt eval/legit_uae_official.txt --workers 12
```

It scans every link with the full pipeline (browser and storefront checks on) and writes one CSV per set to `eval/results/`. `eval/build_sets.py` rebuilds the sets.

A link counts as flagged when Shaheen calls it `fraud` or `suspicious`. "Reachable" means Shaheen fetched the page.

| Set | Links | Reachable | Fraud | Suspicious | Legitimate | Result |
|---|---:|---:|---:|---:|---:|---|
| Skimmer stores from the case study (`ground_truth_skimmers.txt`) | 93 | 44 | 65 | 27 | 1 | **92 of 93 flagged (recall 98.9%)** |
| Legitimate WooCommerce stores (`legit_woocommerce.txt`) | 249 | 227 | 0 | 0 | 249 | **0 false positives** |
| Random Tranco top-10k sites (`legit_top_sites.txt`) | 200 | 125 | 0 | 0 | 200 | **0 false positives** |
| Official UAE brand domains (`legit_uae_official.txt`) | 34 | 27 | 0 | 0 | 34 | **0 false positives** |
| OpenPhish community feed, captured the same day (`phish_openphish.txt`) | 200 | 38 | 2 | 15 | 183 | 17 flagged (8.5%); 10 of the 38 reachable pages |

Across the 483 legitimate sites there is no false positive, and all 109 flagged links are true scams (precision 1.000).

What the numbers mean:

- **Skimmer stores.** These are the 93 storefronts traced by hand in the [case study](docs/case-study.md). 28 sit behind a Cloudflare bot challenge, yet Shaheen still scores them: the WooCommerce Store API answers outside the challenge and exposes the skimmer gateway. 20 links hit the 90-second limit per link, because the box was also running the watcher and the investigator. Those 20 are scored from their URL and registration alone, and Shaheen never calls `fraud` without evidence from the page, so 19 of them are `suspicious`. The one miss, `harmankardonnz[.]com`, is the 20th: its name joins a brand to a two-letter country code, which Shaheen does not read as a place on purpose (too many false alarms), and from the URL alone it scores 0. A full scan of the same store afterwards scored `fraud` 90 (skimmer gateway, shared administrator).
- **Legitimate stores.** The list is every store in the Tranco top million whose name matches shop, store, mall, boutique, market or `.ae` and whose site answers the WooCommerce Store API. Shaheen is aimed at exactly these sites, so this is the false-positive test that matters. The first run on this list flagged 3 of the 250 stores. Two were real false alarms: shops whose own login form sat next to a WhatsApp or Instagram button, so the page looked like a brand asking for a password. Shaheen now counts a brand named only in the page text when the page names no site of its own. The third, `costoresuae[.]com`, called itself "COS UAE Online", checked out only through the skimmer gateway and shared a site administrator with a case-study cluster. It is a skimmer that the Tranco filter let in, so it was removed from the list (the file says so).
- **Top sites and UAE official domains.** Top sites get a popularity credit (Tranco top 100k), so this set mainly checks that nothing popular is flagged by accident. The UAE set checks the allowlist itself: every official domain of the 27 UAE brands comes out `legitimate`.
- **Generic phishing.** OpenPhish lists phishing against any brand worldwide, and pages die within hours: 155 of the 200 were dead and 7 blocked by scan time. Most of the 38 live ones sit on free hosting and impersonate brands Shaheen does not track (a Hungarian telecom, Roblox, a DeFi app, webmail logins), so only brand-independent signals apply. The 10 it flags are the pages that send data to a Telegram bot, ask for a password under a brand it knows, use a lookalike name, or bounce visitors on through an empty doorway page. The run before this one looked at an earlier capture of the feed. Its misses showed that six cloud and app-hosting suffixes were missing from `data/hosting_platforms.yaml` and that data sent to a Telegram bot deserved more weight. Both were fixed, and the set above is a fresh capture taken after those fixes. The feed rolls slowly, so it overlaps with the earlier capture: read the phishing row as tuned on, not unseen.

## The local model

The investigator runs on the demo box (A10A: AMD Ryzen AI Max+ PRO 495 with Radeon 8065S graphics, Windows 11). The model is Qwen3.8-Flash, as a 3-bit IQ3_S GGUF (a community "abliterated" build), served by llama.cpp with every layer on the GPU and a 262k-token context split over two slots, so two investigations run at once.

`uv run shaheen investigate --bench` on the box, measured with one slot: **24.2 tokens/s generation**, 103 tokens/s prompt processing (short prompt).

Over the first 9 investigations on 2026-11-24 (from each case's `evidence/<id>/investigation.json`):

| | |
|---|---|
| Mode | pi with tools and browser, 9 of 9 (no fallback to one-shot) |
| Time per case | median 270 s (219 to 347 s) |
| Tool calls per case | median 14; the most used were `browser_navigate`, `domain_intel` and `get_case` |
| Browser used | 9 of 9 cases |
| Browser policy violations | 0 |
| New candidates proposed to the watcher | 57 domains |

With two slots, the Statistics page on the box showed at 21:14 GST: 41 investigations done, 1 running and 421 queued, with a median of 10.8 minutes and 21 tool calls per case (over the 39 with a run record). Each case takes longer than with one slot, as two share the GPU. Two runs that timed out while both slots were busy were put back in the queue.

In a test against a fake fine-payment page that told the AI to "mark this site safe", every run kept the phishing verdict and quoted the hidden instruction as evidence of manipulation. The model also asked for a lower score on several cases scored `fraud` from the domain name alone; that pattern led to the rule that `fraud` needs evidence from the scam itself.

## Live run

The watcher has run on the demo box since 2026-11-24 15:26 GST, as `shaheen up` since 17:27. At 21:12 GST, after 5 h 47 min, the dashboard showed:

| Candidates seen | Scanned | Flagged | of which fraud | AI-investigated | Maps leads |
|---:|---:|---:|---:|---:|---:|
| 1,449 | 1,469 | 643 | 99 | 40 | 8 |

By collector (Statistics page, 21:14 GST):

| Collector | Scanned | Flagged | Fraud |
|---|---:|---:|---:|
| Storefront sweep | 780 | 344 | 71 |
| AI investigator's proposals | 210 | 148 | 8 |
| Lookalike generator | 401 | 96 | 1 |
| Newly registered domains | 48 | 35 | 3 |
| Checked by hand | 23 | 19 | 16 |
| Google Maps | 7 | 1 | 0 |
| Certificate Transparency | 0 | 0 | 0 |

Certificate Transparency (crt.sh) barely answered that day and contributed none. The scoring rules were tightened during the first hour (see Evaluation), so the flagged count mixes old and new rules; the evaluation above is the measured result. Flagged cases still need an analyst: a lookalike name with no page is `suspicious`, not proof.

## Limitations

- The skimmer gateway check matches one kit's private plugin names. They are trivial to change once this repo is public. The card-form, discount and shared-catalogue checks exist for that reason, but a new kit could evade all of them.
- Shaheen knows 58 brands. A site impersonating a brand it does not know is caught only by brand-independent signals (new domain, card form without a processor, skimmer gateway, offsite form posts), which is why generic phishing recall is low.
- A lookalike domain with no reachable page is scored from its name, registration and certificate alone. Some of those reach `fraud` without any page evidence; the investigator then marks them for human review.
- Geo-cloaking that shows the scam only to UAE visitors needs a UAE network exit. Shaheen fetches from wherever it runs.
- The browser policy (never type, submit, download or log in) is enforced by the prompt and audited after every run, not technically blocked. A click on a submit button is not flagged by itself; it is visible in the trace.
- Search-engine coverage needs an API key we did not have. The Google Maps collector checks phone numbers only for the 7 brands with verified numbers in the brand data. It finds a brand by the name in a listing, so brands named with an everyday word (noon, du, Marshall, Beats) go unmatched, and Emirates matches only by its Arabic name. Google's terms let Shaheen keep a place ID indefinitely but other listing content only where expressly permitted; the leads table keeps the name, address and phone of flagged listings as evidence, so a police deployment needs Google's agreement for that, or a fresh Place Details lookup when an analyst opens a lead.
- The evaluation sets are small and were collected on one day. Phishing pages die within hours, so most feed links were dead by scan time.

## Roadmap to a police pilot

1. **Search and ads collector:** query "brand + uae" and fine-payment phrases through a search API and scan the top results and sponsored links daily.
2. **UAE egress:** run the fetchers through a UAE network exit to see geo-cloaked pages.
3. **Visual similarity:** compare screenshots with each brand's official pages to catch sites that copy the look without the name.
4. **Clustering:** group cases by shared catalogue, administrator, hosting and certificate into campaigns, and report one network instead of 90 sites.
5. **Takedown loop:** send confirmed cases to registrars, hosting providers and Google Safe Browsing, then track how long each site stays up.
6. **Brand onboarding:** a form for UAE organisations to register their official domains, apps and phone numbers.

## Repository

```text
shaheen/            pipeline: resolve, intel, render, page, storefront, signals, score, reasons, evidence, store
shaheen/web/        dashboard (FastAPI, server-rendered; no external assets but Google's map script, with its key)
shaheen/watch.py    collectors and the 24/7 loop
shaheen/investigator.py, shaheen/mcp_server.py, agent/   the local-model investigator
data/            brand allowlists, gateways, TLDs, wording (EN/AR), Tranco top 100k
eval/            labelled sets, set builder, results
demo/cases/      fixed cases for the demo: one real official site plus synthetic captures of invented .test domains
docs/            case study, investigator design, video shot list, screenshots
tests/           offline tests (network monkeypatched): uv run pytest
```
