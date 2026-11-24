# Case Study: A Fake-Storefront Card-Skimming Network Targeting UAE and Gulf Shoppers

**Status:** prior manual research that motivated Shaheen. First found 30 September 2026; re-measured 24 November 2026.
**Category:** brand impersonation, trademark infringement, payment-card theft, consumer fraud.

All scam domains in this document are defanged (for example `boseuae[.]com`). Do not re-fuse them into working links. Official brand domains such as bose.com are left as written.

## 1. Summary

A network of fake online stores impersonates premium consumer-electronics brands and collects shoppers' card details at checkout. It was found because a Google search for "bose uae" returned a fake store as the number-one result.

- **Scale:** 93 live storefronts on 93 `.com` domains, covering 11 brands and about 50 countries, spread over 19 registrars.
- **Gulf focus:** 14 of the 93 domains target the UAE, Kuwait, Qatar or Saudi Arabia (section 2). The UAE has 9.
- **Card collection:** the checkout asks for card number, expiry and security code in a form on the store's own page, with no recognised payment processor script or embedded processor frame (section 5). No card was submitted during this research.
- **One operation:** the evidence points to one operation rather than separate unrelated sellers. Section 7 separates what is proven from what is inferred.
- **Growing:** 21 of the 93 domains were registered since September 2026. The most recent were registered the day before the November re-check.
- **Not flagged:** at the time of checking, Google Safe Browsing returned no warning for the domains tested, so shoppers saw no browser warning.

## 2. UAE and Gulf domains

These are the domains aimed at Gulf shoppers, with registration dates from public registry (RDAP) records.

| Domain | Brand impersonated | Registered |
|---|---|---|
| `beatsuae[.]com` | Beats | 2026-07-06 |
| `bose-uae[.]com` | Bose | 2026-05-27 |
| `boseae[.]com` | Bose | 2026-11-03 |
| `harmankardonuae[.]com` | Harman Kardon | 2026-04-27 |
| `jbl-uae[.]com` | JBL | 2025-10-18 |
| `jbldubai[.]com` | JBL | 2026-03-14 |
| `marshallsuae[.]com` | Marshall | 2026-09-17 |
| `shark-uae[.]com` | Shark | 2026-04-01 |
| `soundcoredubai[.]com` | Soundcore | 2025-12-23 |
| `bose-kuwait[.]com` | Bose | 2026-05-16 |
| `bosesksa[.]com` | Bose | 2026-07-06 |
| `harmankardonkuwait[.]com` | Harman Kardon | 2026-04-27 |
| `harmankardonqatar[.]com` | Harman Kardon | 2026-04-27 |
| `harmankardonsaudiarabia[.]com` | Harman Kardon | 2026-04-27 |

The search result that started the case, `boseuae[.]com`, is a tiny redirect page. On 24 November 2026 it forwarded visitors to the newest UAE storefront, `boseae[.]com` (registered 3 November 2026). A further storefront from the original find, `bosesuae[.]com`, was still live but is not part of the 93 count. This pattern, a high-ranking doorway that moves its target when a new domain is registered, is one reason a keyword search alone does not close the problem.

## 3. How the network was found

**Trigger.** A natural-language brand search ("bose uae") returned `boseuae[.]com` at the top of the organic results. Its page body is a single automatic redirect to a store. The store showed real brand imagery, discounts of up to about 96 percent, no business identity, and a card form from a plugin that is not part of standard WooCommerce.

**Method.** All checks used non-intrusive reads of public endpoints: public registry records, DNS, certificate data, and the stores' own public WordPress and WooCommerce interfaces. No login was bypassed and no site was accessed beyond what any visitor's browser can request. One interactive step was made early on: an item was added to a cart to view the public checkout page. No personal data was entered and no order was placed.

| Source | Used for |
|---|---|
| DNS lookups | Whether a name is registered; hosting and fronting |
| WHOIS and RDAP | Registrar and registration date |
| HTTP requests | Status, redirects, public pages |
| TLS certificate reads | Issuer and validity |
| WordPress REST interface | Site name, theme, and the public administrator profile (used for linkage) |
| WooCommerce Store API | Which payment methods the store offers, and the product catalogue |
| Google Safe Browsing Transparency Report | Whether browsers warn about each domain |
| Wayback Machine | History of a domain (`boseuae[.]com` was an unrelated recycled domain with spam content in 2019) |
| Screenshots in a normal browser | Visual confirmation of representative stores |

**The discriminator.** Every store in the network exposes the same unusual payment method names through the WooCommerce Store API: `sankee` with `public-payment` on most stores, and `yhp` with `mp` on a European cluster. These are not listed in any public plugin directory that we could find, and none of the brand sites or legitimate stores checked offered them. A domain returning one of these names was treated as confirmed. A domain that did not was not counted.

**Enumeration.** Public certificate-log and reverse-IP lookups were unreliable or blind, because most domains sit behind a CDN. The main method was therefore a deterministic sweep:

1. Generate candidate names from brand, country and naming-pattern combinations.
2. Skip names with no DNS record.
3. For registered names, read the Store API and keep only those exposing the payment method names above.

The three widening sweeps in November checked **22,936 candidate names** (9,280 across 32 brands, 8,640 on alternate top-level domains, and 5,016 closing country gaps for the 11 confirmed brands). The alternate-domain sweep found nothing, so the operation appears to use `.com` only. Earlier sweeps in September and early November are not included in that figure. Fifteen other brands were swept with no hits: Sony, Sonos, Bowers & Wilkins, Bang & Olufsen, Jabra, Shure, Denon, Klipsch, Ultimate Ears, Garmin, GoPro, DJI, Roborock, Ecovacs and Nothing.

## 4. Results on 24 November 2026

### 4.1 Footprint by brand

| Brand | Live domains |
|---|---:|
| Bose | 42 |
| Harman Kardon | 21 |
| Soundcore (Anker) | 8 |
| Marshall | 6 |
| JBL | 4 |
| Anker | 4 |
| Skullcandy | 2 |
| Shark | 2 |
| Dreame | 2 |
| Sennheiser | 1 |
| Beats | 1 |
| **Total** | **93** |

### 4.2 Growth

The first list, on 30 September 2026, had 43 domains. Of that 43, 36 were still live on 24 November, 3 had gone offline and 1 was moving host. The current count is 93.

Registry records show 21 of the 93 domains were registered since September 2026 (10 in September, 7 in October, 4 in November). So the growth reads as **21 newly registered, the rest newly found by a wider sweep**: the remaining domains were registered earlier and were only found once the sweep covered more countries and brands. Registrations overall run from September 2024 to 23 November 2026, with peaks in October 2024 (10), December 2025 (13), April 2026 (20) and July 2026 (11).

New in this period were a second large brand (Harman Kardon, 21 countries), four new brands (Shark, Dreame, Skullcandy, Sennheiser), a second payment-method name (`yhp`), and some domains moving from CDN fronting to direct hosting. Three September domains went offline. The report was not filed during this window, and the network grew over it.

### 4.3 Registrars

Registrars are listed as recorded in RDAP, with the number of the 93 domains each holds. No inference is drawn from these names.

| Registrar | Domains |
|---|---:|
| Spaceship, Inc. | 13 |
| Vantage of Convergence (Chengdu) Technology Co., Ltd. | 11 |
| Bangning Digital Technology Co.,Ltd | 9 |
| BF Internet Limited | 9 |
| Guizhou Zhongyu Zhike Network Technology Co., Ltd. | 9 |
| EU Technology (HK) Limited | 9 |
| Cloud Yuqu LLC | 5 |
| Realtime Register B.V. | 4 |
| Xin Net Technology Corporation | 4 |
| CNOBIN INFORMATION TECHNOLOGY LIMITED | 3 |
| Xiamen 35.com Information Co., Ltd. | 3 |
| TuringSign Inc. d/b/a Cosmotown | 3 |
| Bizcn.com, Inc. | 3 |
| Hosting Concepts B.V. d/b/a Registrar.eu | 2 |
| NameSilo, LLC | 2 |
| Dominet (HK) Limited | 1 |
| Gransy, s.r.o. | 1 |
| Chengdu West Dimension Digital Technology Co., Ltd. | 1 |
| PDR Ltd. d/b/a PublicDomainRegistry.com | 1 |

### 4.4 Hosting

Most domains are fronted by Cloudflare. A growing subset resolves directly to a small number of hosting networks, including Fiber Grid Inc, a "SE/CDN" address block and a broadband provider. Fiber Grid also hosted `boseuae[.]com` in 2024. Origin addresses are held in the research files and are suitable for abuse reports and legal process. Most stores report the same server timezone setting; newer ones set a timezone matching the target country.

## 5. Where card data goes: what the checkout shows

No card was submitted, so no transmission was observed. What follows is what can be read in a saved copy of one store's checkout page and the gateway plugin's script files.

**Fields collected.** The checkout form collects billing name, address, city, region, postcode, country, phone and email, with an optional account password and optional separate shipping name. The card section collects card number, expiry date and security code, as ordinary text boxes on the page. Three hidden fields are also present: screen size, timezone offset and a plugin version.

**Where the form goes.** The form is submitted to the store's own checkout address. The page loads 48 scripts, every one from the store's own domain. It contains no embedded frame. There is no script, hosted field or frame from a recognised payment processor. Card fields rendered by a legitimate processor are normally served from the processor's domain so the merchant never handles the number. Here the merchant domain handles it directly.

**The two payment options.** The page offers two methods, `sankee` (credit card form) and `public-payment` (labelled as credit card or PayPal). No PayPal script is loaded on the page.

**What the plugin's scripts do.** The gateway plugin ships three scripts. Two format and check the card inputs as the shopper types, using a generic open-source card-formatting library. The third reads the browser's screen size and timezone and writes them into the hidden fields, which is a form of device profiling. None of the three contacts a payment processor.

**What this does not show.** The saved files cannot show what the store's server does with the card data after submission, because that code runs server-side and was not accessed. The accurate statement is this: card data is entered into a form served by the scam domain itself, is submitted to that domain's server, and no processor script is present that would hand it to an accredited third party. That is consistent with card capture, but it is an inference from the page, not an observed transfer.

## 6. Link to Shaheen

## What Shaheen re-detects

Shaheen automates the checks in section 3. The results of that automated re-detection, including how many of the domains above it finds and the false-positive rate, are reported in the README evaluation section: [../README.md#evaluation](../README.md#evaluation). No figures are repeated here.

False positives are measured on a set of legitimate WooCommerce stores; see the README evaluation section.

## 7. Attribution: proven and inferred

**Proven (observed directly):**
- 24 or more of the Bose stores share a single administrator account fingerprint (cluster A) from the public WordPress user interface, and carry a byte-identical product catalogue.
- The wider network shares private payment plugin names found in no public directory, the same store theme and the same CDN fronting.
- A common hosting provider appears across the operation and in the 2024 history of `boseuae[.]com`.

**Inferred (not proven):**
- That the remaining domains, which do not share the administrator fingerprint, belong to the same operation. They are linked by shared kit and infrastructure, not by an account match.
- That a second payment-method name (`yhp`) is a newer variant from the same operation rather than a separate one.

**Not established:** the identity of any person. None can be derived from the public sources used here (privacy-protected registrations, CDN fronting, no profile leakage). Names are obtainable only through legal process directed at registrars, the CDN, the payment back end or the plugin's author.

## 8. Limitations

- The sweep covers a fixed matrix of brands, countries and naming patterns on `.com`. The true footprint is likely larger, and 93 should be read as a floor.
- Liveness is a point-in-time check on 24 November 2026.
- The checkout analysis rests on one store's saved page and its plugin files. The other stores run the same plugin names but were not each saved and compared.
- Safe Browsing status was checked on a sample at one point in time.
- No financial-loss figure is stated; none was measured and no order data was accessed.

## 9. Recommended actions

1. Report to the CDN that fronts most domains, as card theft and phishing.
2. Report to Google Safe Browsing, the registrar abuse desks and the impersonated brands' fraud teams.
3. Notify national cyber and police authorities in the targeted countries, starting with the UAE.
4. Alert card networks, and advise anyone who entered a card on these sites to contact their bank.

## Appendix: the 93 live domains

All `.com`, defanged, grouped by brand.

**Bose (42):** `bose-ar[.]com` · `bose-colombia[.]com` · `bose-egypt[.]com` · `bose-elsalvador[.]com` · `bose-greece[.]com` · `bose-india[.]com` · `bose-kuwait[.]com` · `bose-malaysia[.]com` · `bose-nz[.]com` · `bose-portugal[.]com` · `bose-uae[.]com` · `bose-usa[.]com` · `boseae[.]com` · `boseaustria[.]com` · `bosebangladesh[.]com` · `bosebelgium[.]com` · `bosechile[.]com` · `bosecostarica[.]com` · `boseecuador[.]com` · `boseelsalvador[.]com` · `bosefinland[.]com` · `boseguatemala[.]com` · `boseireland[.]com` · `boseisrael[.]com` · `boseitaly[.]com` · `bosenorway[.]com` · `bosepanama[.]com` · `boseperu[.]com` · `bosesargentina[.]com` · `boseschile[.]com` · `bosescolombia[.]com` · `bosesfrance[.]com` · `bosesingapore[.]com` · `bosesksa[.]com` · `bosesmalaysia[.]com` · `bosesmexico[.]com` · `bosespain[.]com` · `bosesthailand[.]com` · `bosesuruguay[.]com` · `boseswitzerland[.]com` · `bosetr[.]com` · `boseturkey[.]com`

**Harman Kardon (21):** `harmankardon-indonesia[.]com` · `harmankardon-ireland[.]com` · `harmankardonargentina[.]com` · `harmankardonaustralia[.]com` · `harmankardonbelgium[.]com` · `harmankardoncanada[.]com` · `harmankardonchile[.]com` · `harmankardoncolombia[.]com` · `harmankardonecuador[.]com` · `harmankardonegypt[.]com` · `harmankardonfrance[.]com` · `harmankardonhungary[.]com` · `harmankardonkuwait[.]com` · `harmankardonmalaysia[.]com` · `harmankardonnz[.]com` · `harmankardonperu[.]com` · `harmankardonphilippines[.]com` · `harmankardonqatar[.]com` · `harmankardonsaudiarabia[.]com` · `harmankardonsingapore[.]com` · `harmankardonuae[.]com`

**Soundcore (8):** `soundcore-dk[.]com` · `soundcore-fr[.]com` · `soundcore-tr[.]com` · `soundcorebe[.]com` · `soundcoredenmark[.]com` · `soundcoredubai[.]com` · `soundcorepoland[.]com` · `soundcorept[.]com`

**Marshall (6):** `marshallegypt[.]com` · `marshalllebanon[.]com` · `marshallmalta[.]com` · `marshallromania[.]com` · `marshallslovenia[.]com` · `marshallsuae[.]com`

**JBL (4):** `jbl-netherlands[.]com` · `jbl-uae[.]com` · `jbldubai[.]com` · `jblgermany[.]com`

**Anker (4):** `anker-gr[.]com` · `ankerczech[.]com` · `ankerhu[.]com` · `ankernl[.]com`

**Skullcandy (2):** `skullcandy-mexico[.]com` · `skullcandysweden[.]com`

**Shark (2):** `shark-uae[.]com` · `sharkfrance[.]com`

**Dreame (2):** `dreameaustralia[.]com` · `dreameireland[.]com`

**Sennheiser (1):** `sennheisernetherlands[.]com`

**Beats (1):** `beatsuae[.]com`


