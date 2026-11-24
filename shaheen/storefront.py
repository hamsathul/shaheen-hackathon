"""Fake brand stores that skim cards: checks on a WooCommerce store's public
endpoints, the same ones any visitor's browser can request.

Every check is an unauthenticated GET that fails soft: nothing is posted,
nothing is added to a cart and no form is submitted. Raw administrator
avatar hashes stay in the local database; evidence files show only a
derived cluster ID.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

from shaheen import brands, page, signals
from shaheen.config import DATA_DIR
from shaheen.domains import host_of
from shaheen.models import Finding, ScanContext
from shaheen.store import Store

TIMEOUT = 8.0
MAX_JSON = 5_000_000
PRODUCTS_SAMPLE = 50
DEEP_DISCOUNT = 0.70
MIN_PRICED = 5
WC_STORE_NAMESPACES = ("wc/store", "wc/store/v1")
ROOT_FIELDS = "name,timezone_string,gmt_offset,namespaces"
_AVATAR_HASH = re.compile(r"/avatar/([0-9a-f]{32,64})", re.I)
# Gravatar hashes of an empty e-mail address (MD5 and SHA-256): shared by unrelated sites.
_EMPTY_HASHES = frozenset({
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
})


@dataclass(frozen=True)
class Processor:
    name: str
    hosts: tuple[str, ...]
    slugs: tuple[str, ...]


@lru_cache(maxsize=1)
def gateway_lists() -> dict[str, frozenset[str]]:
    data = yaml.safe_load((DATA_DIR / "skimmer_gateways.yaml").read_text(encoding="utf-8"))
    return {"strong": frozenset(data["strong"]), "weak": frozenset(data["weak"])}


@lru_cache(maxsize=1)
def processors() -> tuple[Processor, ...]:
    data = yaml.safe_load((DATA_DIR / "payment_processors.yaml").read_text(encoding="utf-8"))
    return tuple(Processor(p["name"], tuple(p["hosts"]), tuple(p["slugs"])) for p in data["processors"])


def _slug_matches(slug: str, known: str) -> bool:
    return slug == known or slug.startswith((known + "_", known + "-"))


def processor_for_slug(slug: str) -> str | None:
    slug = slug.lower()
    return next((p.name for p in processors() if any(_slug_matches(slug, s) for s in p.slugs)), None)


def processor_for_url(url: str) -> str | None:
    """The processor serving a script or frame URL (`https://js.stripe.com/v3/`)."""
    parts = urlsplit(url if "://" in url else "https://" + url)
    host, path = (parts.hostname or "").lower(), parts.path
    for p in processors():
        for entry in p.hosts:
            h, _, prefix = entry.partition("/")
            if (host == h or host.endswith("." + h)) and (not prefix or path.lstrip("/").startswith(prefix)):
                return p.name
    return None


def classify_gateways(slugs: list[str]) -> dict[str, list[str]]:
    """Each payment method slug as strong (skimmer), weak, recognised (a known processor) or unknown."""
    lists = gateway_lists()
    out: dict[str, list[str]] = {"strong": [], "weak": [], "recognised": [], "unknown": []}
    for slug in slugs:
        if slug.lower() in lists["strong"]:
            out["strong"].append(slug)
        elif slug.lower() in lists["weak"]:
            out["weak"].append(slug)
        elif processor_for_slug(slug):
            out["recognised"].append(slug)
        else:
            out["unknown"].append(slug)
    return out


def _payment_slugs(cart: Any) -> list[str]:
    methods = cart.get("payment_methods") if isinstance(cart, dict) else None
    slugs = []
    for m in methods or []:
        slug = m if isinstance(m, str) else (m.get("id") or m.get("name") if isinstance(m, dict) else None)
        if isinstance(slug, str) and slug:
            slugs.append(slug)
    return list(dict.fromkeys(slugs))


def _amount(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def price_stats(products: Any) -> dict[str, Any]:
    """How many sampled products carry a price and how many are discounted by more than 70%."""
    discounts = []
    for item in products if isinstance(products, list) else []:
        prices = item.get("prices") if isinstance(item, dict) else None
        if not isinstance(prices, dict):
            continue
        price, regular = _amount(prices.get("price")), _amount(prices.get("regular_price"))
        if price is None or not regular or regular <= 0:
            continue
        discounts.append(1 - price / regular)
    deep = sum(1 for d in discounts if d > DEEP_DISCOUNT)
    return {
        "sampled": len(products) if isinstance(products, list) else 0,
        "priced": len(discounts),
        "deep_discounted": deep,
        "share": round(100 * deep / len(discounts)) if discounts else 0,
        "max_discount": round(100 * max(discounts)) if discounts else None,
    }


def deep_discount_findings(stats: dict[str, Any]) -> list[Finding]:
    if stats["priced"] >= MIN_PRICED and stats["deep_discounted"] * 2 > stats["priced"]:
        return [Finding("DEEP_DISCOUNTS", "storefront.json#prices", {"share": stats["share"]})]
    return []


def catalogue_hash(products: Any) -> str | None:
    """SHA-256 of the sorted `sku|name` lines of the first 50 products by id."""
    items = [p for p in products if isinstance(p, dict)] if isinstance(products, list) else []
    items = sorted(items, key=lambda p: p.get("id") if isinstance(p.get("id"), int) else 0)[:PRODUCTS_SAMPLE]
    lines = sorted(f"{p.get('sku') or ''}|{p.get('name') or ''}" for p in items)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest() if lines else None


def admin_hashes(users: Any) -> list[str]:
    """Gravatar hashes of the public user profiles (raw: for the local database only)."""
    found = []
    for user in users if isinstance(users, list) else []:
        urls = user.get("avatar_urls") if isinstance(user, dict) else None
        for url in (urls or {}).values() if isinstance(urls, dict) else []:
            m = _AVATAR_HASH.search(str(url))
            if m and m.group(1).lower() not in _EMPTY_HASHES:
                found.append(m.group(1).lower())
    return list(dict.fromkeys(found))


def cluster_id(kind: str, value: str) -> str:
    """The shareable ID of a fingerprint: `A-` for an administrator, `C-` for a catalogue."""
    prefix = {"admin": "A", "catalogue": "C"}[kind]
    return f"{prefix}-{hashlib.sha256(f'{kind}:{value}'.encode()).hexdigest()[:8]}"


def checkout_facts(html: str, url: str, slugs: list[str]) -> dict[str, Any]:
    """The card fields of a checkout page and the processors it uses."""
    facts = page.analyse(html, url)
    kinds = facts.field_kinds()
    card = sorted(kinds & {"number", "expiry", "cvv"})
    seen = {processor_for_url(u) for u in facts.scripts + facts.iframes}
    seen |= {processor_for_url(h) for h in re.findall(r"(?:https?:)?//([a-z0-9.-]+\.[a-z]{2,}/?[\w/-]*)",
                                                      facts.inline_script, re.I)}
    seen |= {processor_for_slug(s) for s in slugs}
    seen.discard(None)
    return {
        "url": url,
        "form": "visible" if {"number", "cvv"} <= kinds else "not_visible",
        "card_fields": card,
        "processors": sorted(seen),
        "script_hosts": facts.hosts(facts.scripts),
        "iframe_hosts": facts.hosts(facts.iframes),
    }


def storefront_brand(host: str, site_name: str) -> str | None:
    """The product brand a store trades on: in its domain or its WordPress site name."""
    for m in brands.match_domain(host):
        if m.brand.scope == "storefront":
            return m.brand.name_en
    found = signals.find_brands(site_name or "", scopes=("storefront",))
    return found[0][0].name_en if found else None


@dataclass
class _Fetcher:
    client: httpx.Client
    origin: str
    rest_style: str = "pretty"  # pretty: /wp-json/<route>; query: /?rest_route=/<route>
    errors: dict[str, str] = field(default_factory=dict)

    def get(self, url: str, name: str, tries: int = 1) -> httpx.Response | None:
        """GET with one more try after a timeout when `tries` is 2 (slow shared hosts)."""
        for attempt in range(tries):
            try:
                resp = self.client.get(url, timeout=TIMEOUT, follow_redirects=True,
                                       headers={"Accept": "application/json, text/html;q=0.9"})
            except httpx.TimeoutException as exc:
                self.errors[name] = f"{type(exc).__name__} after {attempt + 1} tries"
                continue
            except httpx.HTTPError as exc:
                self.errors[name] = f"{type(exc).__name__}: {exc}"[:200]
                return None
            self.errors.pop(name, None)
            return resp
        return None

    def rest(self, route: str, name: str, query: str = "", tries: int = 1) -> Any:
        if self.rest_style == "pretty":
            url = f"{self.origin}/wp-json{route}" + (f"?{query}" if query else "")
        else:
            url = f"{self.origin}/?rest_route={route}" + (f"&{query}" if query else "")
        resp = self.get(url, name, tries)
        if resp is None:
            return None
        if resp.status_code != 200 or len(resp.content) > MAX_JSON:
            self.errors[name] = f"HTTP {resp.status_code}"
            return None
        try:
            return resp.json()
        except ValueError:
            self.errors[name] = "not JSON"
            return None


def _wp_root(fetcher: _Fetcher) -> dict[str, Any] | None:
    """The WordPress REST index (only the fields Shaheen reads), with pretty
    permalinks or, when those answer with something else, without."""
    for style in ("pretty", "query"):
        fetcher.rest_style = style
        root = fetcher.rest("/", "wp_json", f"_fields={ROOT_FIELDS}", tries=2)
        if isinstance(root, dict) and "namespaces" in root:
            return root
        if "Timeout" in fetcher.errors.get("wp_json", ""):
            break
    fetcher.rest_style = "pretty"
    return None


def inspect(ctx: ScanContext, client: httpx.Client, store: Store) -> None:
    """Run the storefront checks on the landing site and record findings,
    fingerprints and `storefront.json` on the scan. The requests go one after
    another, so a store on a slow shared host is not hit all at once."""
    parts = urlsplit(ctx.final_url)
    fetcher = _Fetcher(client, f"{parts.scheme}://{parts.netloc}")
    root = _wp_root(fetcher)
    namespaces = root.get("namespaces", []) if root else []
    cart = None
    if root is None:  # the index is blocked or too slow: the Store API cart alone shows WooCommerce
        cart = fetcher.rest("/wc/store/v1/cart", "cart", tries=2)
    woo = any(ns in namespaces for ns in WC_STORE_NAMESPACES) or (isinstance(cart, dict)
                                                                  and "payment_methods" in cart)
    if not woo:
        ctx.artifacts["storefront.json"] = {"origin": fetcher.origin, "woocommerce": False,
                                            "wordpress": root is not None, "errors": fetcher.errors}
        ctx.features["storefront"] = {"woocommerce": False}
        return

    if cart is None:
        cart = fetcher.rest("/wc/store/v1/cart", "cart", tries=2)
    products = fetcher.rest("/wc/store/v1/products", "products", f"per_page={PRODUCTS_SAMPLE}")
    users = fetcher.rest("/wp/v2/users", "users")
    checkout = fetcher.get(f"{fetcher.origin}/checkout/", "checkout")
    root = root or {}

    slugs = _payment_slugs(cart)
    gateways = classify_gateways(slugs)
    site_name = str(root.get("name") or "")
    brand = storefront_brand(host_of(ctx.final_url), site_name)
    check = {"url": f"{fetcher.origin}/checkout/", "form": "unavailable"}
    if checkout is not None and checkout.status_code == 200:
        check = checkout_facts(checkout.text, str(checkout.url), slugs)
    stats = price_stats(products)
    catalogue = catalogue_hash(products)
    admins = admin_hashes(users)

    domain = ctx.features["final_domain"]
    prints = [("catalogue", catalogue)] if catalogue else []
    prints += [("admin", h) for h in admins]
    shared = _shared(store, domain, prints)
    store.add_fingerprints(ctx.id, domain, [("gateway", s) for s in slugs] + prints)
    _record(ctx, store_findings(gateways, check, brand, stats, shared), brand)
    ctx.artifacts["storefront.json"] = {
        "origin": fetcher.origin,
        "woocommerce": True,
        "site_name": site_name,
        "timezone": root.get("timezone_string") or None,
        "gmt_offset": root.get("gmt_offset"),
        "storefront_brand": brand,
        "payment_methods": slugs,
        "gateways": gateways,
        "checkout": check,
        "prices": stats,
        "catalogue": {"hash": catalogue, "cluster": cluster_id("catalogue", catalogue)} if catalogue else None,
        "admin_clusters": [cluster_id("admin", h) for h in admins],
        "shared_with_fraud": shared,
        "errors": fetcher.errors,
    }
    ctx.features["storefront"] = {"woocommerce": True, "payment_methods": slugs, "storefront_brand": brand,
                                  "checkout_form": check["form"]}


def store_findings(gateways: dict[str, list[str]], check: dict[str, Any], brand: str | None,
                   stats: dict[str, Any], shared: list[dict[str, Any]]) -> list[Finding]:
    """The storefront signals of a store's gateways, checkout, prices and shared fingerprints."""
    found: list[Finding] = []
    if gateways["strong"]:
        found.append(Finding("SKIMMER_GATEWAY", "storefront.json#payment_methods",
                             {"gateway": gateways["strong"][0]}))
    elif gateways["weak"]:
        found.append(Finding("WEAK_GATEWAY", "storefront.json#payment_methods", {"gateway": gateways["weak"][0]}))
    if check.get("form") == "visible" and not check.get("processors") and brand:
        found.append(Finding("CARD_FORM_NO_PROCESSOR", "storefront.json#checkout"))
    found += deep_discount_findings(stats)
    for item in shared[:1]:
        evidence = "storefront.json#catalogue" if item["kind"] == "catalogue" else "storefront.json#admin_clusters"
        found.append(Finding("SHARED_FINGERPRINT", evidence, {"kind": item["kind"], "cluster": item["cluster"]}))
    return found


def _record(ctx: ScanContext, found: list[Finding], brand: str | None) -> None:
    ctx.findings += found
    if found and brand:
        ctx.impersonated_brand = brand


def replay(ctx: ScanContext, saved: dict[str, Any], store: Store) -> None:
    """The storefront checks of a re-analysis, from the capture's
    `storefront.json` instead of the store's endpoints. Gateways are classified
    again against the current lists; the checkout, prices and fingerprints
    shared with fraud are taken as captured."""
    if not saved.get("woocommerce"):
        ctx.artifacts["storefront.json"] = saved
        ctx.features["storefront"] = {"woocommerce": False}
        return
    slugs = [s for s in saved.get("payment_methods") or [] if isinstance(s, str)]
    gateways = classify_gateways(slugs)
    check = saved.get("checkout") or {"form": "unavailable"}
    brand = storefront_brand(host_of(ctx.final_url), str(saved.get("site_name") or ""))
    catalogue = (saved.get("catalogue") or {}).get("hash")
    prints = [("gateway", s) for s in slugs] + ([("catalogue", catalogue)] if catalogue else [])
    store.add_fingerprints(ctx.id, ctx.features["final_domain"], prints)
    _record(ctx, store_findings(gateways, check, brand, saved.get("prices") or price_stats([]),
                                saved.get("shared_with_fraud") or []), brand)
    ctx.artifacts["storefront.json"] = {**saved, "storefront_brand": brand, "gateways": gateways}
    ctx.features["storefront"] = {"woocommerce": True, "payment_methods": slugs, "storefront_brand": brand,
                                  "checkout_form": check.get("form")}


def _shared(store: Store, domain: str, prints: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Fingerprints this site shares with another domain whose latest scan is
    fraud or analyst-confirmed, by derived cluster ID only."""
    out = []
    for kind, value in prints:
        fraud = []
        for other in store.domains_sharing(kind, value, exclude_domain=domain):
            latest = store.latest_scan_for(other)
            if latest and (latest.verdict == "fraud" or latest.analyst_confirmed):
                fraud.append(other)
        if fraud:
            out.append({"kind": kind, "cluster": cluster_id(kind, value), "domains": sorted(fraud)})
    return out
