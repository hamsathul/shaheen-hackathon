import asyncio
import io
import json
import zipfile

import httpx

from shaheen import mcp_server
from shaheen.config import Settings
from shaheen.hunter import HuntReport, Suspect, verify_suspects
from shaheen.store import Store

# Domains here are made up, under the reserved .test TLD.
NEW_DOMAINS = ["uaevisa-renew.test", "dubai-visa-centre.test", "garden-tools.test"]


def _zip(lines: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("domain-names.txt", "\n".join(lines))
    return buf.getvalue()


def _call(server, tool: str, **args) -> str:
    return asyncio.run(server.call_tool(tool, args)).content[0].text


def test_a_hunt_searches_new_domains_and_records_what_it_queues(tmp_path, monkeypatch):
    settings = Settings(db_path=tmp_path / "shaheen.db", evidence_dir=tmp_path / "evidence", llm_base_url="",
                        llm_model="", llm_api_key="", http_timeout=5, user_agent="test")
    store = Store(settings.db_path)
    hunt_id = store.add_hunt("fake visa renewal sites", "visa_residency")
    downloads = []

    def fake_get(url, **kwargs):
        downloads.append(url)
        return httpx.Response(200, content=_zip(NEW_DOMAINS))

    monkeypatch.setattr(mcp_server.httpx, "get", fake_get)
    server = mcp_server.build_server(settings, hunt_id=hunt_id)
    found = json.loads(_call(server, "search_new_domains", words=["visa"]))
    _call(server, "search_new_domains", words=["uae"])
    assert [d["host"] for d in found["domains"]] == ["uaevisa-renew.test", "dubai-visa-centre.test"]
    assert found["domains"][0]["themes"] == ["visa_residency"] and len(downloads) == 1

    monkeypatch.setattr(mcp_server, "is_registered", lambda domain, resolver: domain == "uaevisa-renew.test")
    queued = json.loads(_call(server, "propose_candidates", domains=["uaevisa-renew.test", "uaevisa-renewal.test"],
                              reason="visa renewal with a UAE name"))
    assert (queued["accepted"], queued["not_registered"]) == (1, 1)
    assert [(f["domain"], f["reason"]) for f in store.hunt_finds(hunt_id)] == [
        ("uaevisa-renew.test", "visa renewal with a UAE name")]
    assert store.claim_candidate()["source"] == "hunt"
    assert "may only report on hunt" in _call(server, "submit_hunt_report", id=hunt_id + 1,
                                              report={"summary_en": "x", "summary_ar": "x"})


def test_suspects_missing_from_every_tool_result_are_dropped():
    report = HuntReport(summary_en="x", summary_ar="x", suspects=[
        Suspect(domain="uaevisa-renew.test", reason="seen"), Suspect(domain="made-up.test", reason="guessed")])
    assert verify_suspects(report, '{"host": "uaevisa-renew[.]test"}') == ["made-up.test"]
    assert [s.domain for s in report.suspects] == ["uaevisa-renew.test"]
