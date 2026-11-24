import json

import httpx
import pytest

from baaz.collectors import Limits, maps
from baaz.store import Store

# Invented listings: made-up names, numbers and .test websites around real brands
# from the brand data. Emirates NBD and RAKBANK have verified numbers; ADCB has none.


def listing(place_id, name, phone="", website="", status="OPERATIONAL", national=False):
    place = {"id": place_id, "displayName": {"text": name, "languageCode": "en"}, "businessStatus": status,
             "formattedAddress": "Invented Street, Dubai", "googleMapsUri": f"https://maps.google.com/?cid={place_id}"}
    if phone:
        place["nationalPhoneNumber" if national else "internationalPhoneNumber"] = phone
    if website:
        place["websiteUri"] = website
    return place


@pytest.mark.parametrize("raw, expected", [
    ("+971 4 000 0199", "+97140000199"),
    ("04 000 0199", "+97140000199"),
    ("(04) 000-0199", "+97140000199"),
    ("600 54 0000", "+971600540000"),
    ("800 2626", "+9718002626"),
    ("999", "+971999"),
    ("00971 50 000 0000", "+971500000000"),
    ("971 4 000 0199", "+97140000199"),
    ("٠٤ ٠٠٠ ٠١٩٩", "+97140000199"),
    ("+44 20 0000 0000", "+442000000000"),
    ("", ""),
    ("n/a", ""),
])
def test_phone_numbers_become_e164_with_the_uae_as_default(raw, expected):
    assert maps.e164(raw) == expected


@pytest.mark.parametrize("name, claims", [
    ("Emirates NBD Customer Care", True),
    ("RAKBANK 24/7 Helpline", True),
    ("ADCB Call Center", True),
    ("Bose Support", True),
    ("خدمه عملاء بنك رأس الخيمة الوطني", True),  # ه for ة, as people type it
    ("مركز إتصال المشرق", True),  # إ folds to ا
    ("Abu Dhabi Police Service Centre", False),
    ("Emirates NBD - Al Barsha Branch", False),
    ("Supported Living Dubai", False),
])
def test_helpline_claims_in_english_and_arabic(name, claims):
    assert maps.claims_helpline(name) is claims


@pytest.mark.parametrize("place, brand, reasons", [
    # A real-looking listing that keeps the official website but shows another number.
    (listing("a", "Emirates NBD Customer Care", "+971 4 000 0199", "https://www.emiratesnbd.com/en/contact-us"),
     "Emirates NBD", ("helpline",)),
    (listing("b", "خدمه عملاء بنك رأس الخيمة الوطني", "٠٤ ٠٠٠ ٠١٩٩", national=True), "RAKBANK", ("helpline",)),
    (listing("c", "ADCB Card Services", "04 000 0123", "https://adcb-cards.test/apply", national=True),
     "Abu Dhabi Commercial Bank (ADCB)", ("website",)),
    (listing("d", "RAKBANK Helpline", "+971 50 000 0000", "https://sites.google.com/view/rak-help"),
     "RAKBANK", ("website", "helpline")),
])
def test_listings_that_become_leads(place, brand, reasons):
    lead = maps.classify(place)
    assert (lead.brand, lead.reasons) == (brand, reasons)
    assert lead.place_id == place["id"] and lead.maps_url == place["googleMapsUri"]


@pytest.mark.parametrize("place", [
    # The brand's own number and website.
    listing("e", "Emirates NBD Customer Care", "+971 600 54 0000", "https://www.emiratesnbd.com/"),
    # A branch with a local number claims no helpline.
    listing("f", "Emirates NBD - Al Barsha Branch", "+971 4 000 0123", "https://www.emiratesnbd.com/"),
    # A helpline claim for a brand with no verified number cannot be checked on the phone.
    listing("g", "ADCB Customer Service", "+971 4 000 0123"),
    # Names no watched brand.
    listing("h", "Quick Fix Phone Repair", "+971 4 000 0123", "https://quickfix.test/"),
    # Permanently closed.
    listing("i", "ADCB Card Services", website="https://adcb-cards.test/", status="CLOSED_PERMANENTLY"),
])
def test_listings_that_are_not_leads(place):
    assert maps.classify(place) is None


def test_search_sends_the_documented_request_and_reads_the_listings():
    seen = {}

    def answer(request):
        seen["headers"], seen["body"] = request.headers, json.loads(request.content)
        return httpx.Response(200, json={"places": [listing("a", "ADCB Card Services"), {"displayName": {}}]})

    client = httpx.Client(base_url="https://places.test", transport=httpx.MockTransport(answer),
                          headers={"X-Goog-Api-Key": "k", "X-Goog-FieldMask": maps.FIELD_MASK})
    places = maps.search(client, maps.Query("ADCB customer service", "en"))
    assert [p["id"] for p in places] == ["a"]  # a listing without an id is dropped
    assert seen["headers"]["X-Goog-FieldMask"] == maps.FIELD_MASK and "places.websiteUri" in maps.FIELD_MASK
    assert seen["body"]["textQuery"] == "ADCB customer service" and seen["body"]["regionCode"] == "AE"
    assert set(seen["body"]["locationBias"]["rectangle"]) == {"low", "high"}


def test_search_gives_up_on_an_error_answer():
    client = httpx.Client(base_url="https://places.test", transport=httpx.MockTransport(
        lambda request: httpx.Response(403, json={"error": {"code": 403, "message": "API key not valid."}})))
    assert maps.search(client, maps.Query("ADCB customer service", "en")) is None


def test_collect_queues_lead_websites_once_and_never_rechecks_a_place(tmp_path, monkeypatch):
    places = [
        listing("a", "Emirates NBD Customer Care", "+971 4 000 0199", "https://www.emiratesnbd.com/"),
        listing("c", "ADCB Card Services", website="https://adcb-cards.test/apply"),
        listing("h", "Quick Fix Phone Repair", website="https://quickfix.test/"),
    ]
    calls = []
    monkeypatch.setattr(maps, "search", lambda client, query: calls.append(query) or places)
    store = Store(tmp_path / "t.db")

    assert maps.collect(store, Limits(max_per_run=100, rate=0)) == 1
    assert len(calls) == maps.QUERIES_PER_RUN  # capped whatever the watcher allows
    leads = {lead["place_id"]: lead for lead in store.maps_leads()}
    assert set(leads) == {"a", "c"}
    assert leads["c"]["candidate_status"] == "queued" and leads["a"]["candidate_status"] is None
    assert store.claim_candidate()["source"] == "maps"

    assert maps.collect(store, Limits(max_per_run=100, rate=0)) == 0
    assert store.counters()["maps_leads"] == 2
