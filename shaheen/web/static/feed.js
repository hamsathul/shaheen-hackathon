// Live feed: the counters, the latest scans, the AI investigator panel and the
// Google Maps watch, pushed by /api/feed/stream every 2 seconds. When the stream
// is quiet for 10 seconds the page asks /api/feed itself, every 5 seconds (every
// 2 while a Maps round runs). Everything is built with textContent only, never
// innerHTML; addresses arrive defanged from the server. With a browser key the
// Maps watch loads Google's Maps JavaScript API, the one outside script.
(function () {
  "use strict";
  var VERDICTS = ["fraud", "suspicious", "legitimate"];
  var T = JSON.parse(document.getElementById("strings").textContent);
  var NONCE = document.currentScript ? document.currentScript.nonce : "";
  var body = document.getElementById("feed-rows");
  var live = document.getElementById("live");
  var watch = document.getElementById("maps-watch");
  var seen = {};
  var calls = {};  // tool calls already shown per running case, to mark the new ones
  Array.prototype.forEach.call(body.querySelectorAll("tr[data-id]"), function (tr) {
    seen[tr.getAttribute("data-id")] = true;
  });

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function cell(text, cls) {
    return el("td", cls, text);
  }

  function mark(verdict, label) {
    return el("span", "mark " + (VERDICTS.indexOf(verdict) >= 0 ? verdict : ""), label);
  }

  function caseLink(r) {
    var link = el("a", "domain", r.domain);
    link.href = "/case/" + encodeURIComponent(r.id);
    link.dir = "ltr";
    return link;
  }

  function row(r) {
    var tr = document.createElement("tr");
    tr.setAttribute("data-id", r.id);
    if (!seen[r.id]) tr.className = "fresh";
    var time = cell(r.time, "time");
    time.dir = "ltr";
    tr.appendChild(time);
    var domain = cell("", "domain");
    domain.dir = "ltr";
    var link = document.createElement("a");
    link.href = "/case/" + encodeURIComponent(r.id);
    link.textContent = r.domain;
    domain.appendChild(link);
    if (r.confirmed) domain.appendChild(el("span", "tick", " ✓"));
    if (r.ai === "done" || r.ai === "running") {
      domain.appendChild(document.createTextNode(" "));
      var tag = el("span", "ai-tag" + (r.ai === "running" ? " running" : ""), "AI");
      tag.title = r.ai === "running" ? T.ai_running : T.investigated;
      domain.appendChild(tag);
    }
    tr.appendChild(domain);
    var verdict = cell("");
    verdict.appendChild(mark(r.verdict, r.verdict_label));
    tr.appendChild(verdict);
    tr.appendChild(cell(String(r.score), "num score"));
    tr.appendChild(cell(r.type));
    tr.appendChild(cell(r.brand));
    var source = cell(r.source, "muted");
    if (r.listing) {
      var listing = el("span", "listing", r.listing);
      listing.dir = "auto";
      source.appendChild(listing);
    }
    tr.appendChild(source);
    return tr;
  }

  function clock(seconds) {
    var s = Math.max(0, Math.floor(seconds));
    var m = Math.floor(s / 60);
    return m + ":" + String(s % 60).padStart(2, "0");
  }

  function tickElapsed() {
    Array.prototype.forEach.call(live.querySelectorAll("[data-started]"), function (node) {
      node.textContent = T.live_elapsed + " " + clock((Date.now() - Number(node.getAttribute("data-started"))) / 1000);
    });
  }

  function aside(cls, text) {  // a line of prose in the LTR log, in the page's language
    var item = el("li", cls, text);
    item.dir = "auto";
    return item;
  }

  // Each block and list item carries a key and a signature of what it shows. A
  // redraw keeps every node whose key and signature are unchanged, and the loaded
  // screenshots of the ones that changed, so nothing on screen flickers.
  function keyed(node, key, shown) {
    node.setAttribute("data-key", key);
    node.setAttribute("data-sig", JSON.stringify(shown));
    return node;
  }

  function patch(holder, nodes, flash) {
    var old = {};
    Array.prototype.forEach.call(holder.children, function (n) {
      if (n.hasAttribute("data-key")) old[n.getAttribute("data-key")] = n;
    });
    var filled = holder.hasAttribute("data-filled");
    var next = nodes.map(function (n) {
      var before = old[n.getAttribute("data-key")];
      if (!before) {
        if (flash && filled) n.classList.add("fresh");
        return n;
      }
      if (before.getAttribute("data-sig") === n.getAttribute("data-sig")) return before;
      Array.prototype.forEach.call(n.querySelectorAll("img"), function (img) {
        var same = Array.prototype.find.call(before.querySelectorAll("img"), function (b) {
          return b.getAttribute("src") === img.getAttribute("src");
        });
        if (same) img.replaceWith(same);
      });
      return n;
    });
    holder.replaceChildren.apply(holder, next);
    holder.setAttribute("data-filled", "");
  }

  function blockHead(r, cls) {
    var block = el("article", cls);
    block.setAttribute("data-id", r.id);
    var head = el("header", "run-head");
    head.appendChild(mark(r.verdict, r.verdict_label));
    head.appendChild(el("span", "run-score", String(r.score)));
    head.appendChild(caseLink(r));
    block.appendChild(head);
    return block;
  }

  function shot(src, caption) {
    var figure = el("figure", "live-shot");
    var img = el("img");
    img.src = src;
    img.alt = caption;
    img.loading = "lazy";
    figure.appendChild(img);
    figure.appendChild(el("figcaption", "label", caption));
    return figure;
  }

  function shots(list) {  // the newest screenshot, then a strip of the ones before it
    var holder = document.createDocumentFragment();
    if (!list.length) return holder;
    holder.appendChild(shot(list[0], T.live_shot));
    if (list.length > 1) {
      var strip = el("p", "shot-strip");
      strip.title = T.live_shots_earlier;
      list.slice(1).forEach(function (src) {
        var link = el("a");
        link.href = src;
        var img = el("img");
        img.src = src;
        img.alt = T.live_shots_earlier;
        img.loading = "lazy";
        link.appendChild(img);
        strip.appendChild(link);
      });
      holder.appendChild(strip);
    }
    return holder;
  }

  function elapsedMeta(work) {
    var meta = el("p", "run-meta");
    var elapsed = el("span", "elapsed");
    elapsed.setAttribute("data-started", String(Date.now() - work.elapsed_s * 1000));
    meta.appendChild(elapsed);
    meta.appendChild(el("span", null, T.live_calls + " " + work.tool_count));
    return meta;
  }

  function note(text) {  // the latest note the model wrote to itself
    var line = el("p", "live-note");
    line.appendChild(el("span", "label", T.live_now));
    var said = el("span", null, text);
    said.dir = "auto";
    line.appendChild(said);
    return line;
  }

  // The tool calls of a run or hunt, newest on top, under what the model is doing now.
  function toolList(work, key) {
    var list = el("ol", "log-tail");
    list.dir = "ltr";
    var first = work.tool_count - work.tools.length;
    var known = calls[key];
    var last = work.tools[work.tools.length - 1];
    if (!last) list.appendChild(aside("note", T.live_starting));
    else if (last.done) list.appendChild(aside("note", T.live_thinking));
    work.tools.slice().reverse().forEach(function (t, i) {
      var n = work.tool_count - i;
      var cls = "call " + (t.error ? "err" : t.done ? "done" : "running");
      if (i === 0) cls += " latest";
      if (known !== undefined && n > known) cls += " fresh";
      var item = el("li", cls);
      item.appendChild(el("span", "n", String(n).padStart(2, "0")));
      item.appendChild(el("span", "server", t.server));
      item.appendChild(el("code", "tool", t.tool));
      var target = el("span", "target", t.target);
      target.title = t.target;
      item.appendChild(target);
      if (t.error) item.appendChild(el("span", "stamp dashed", T.error));
      if (t.said) {
        var said = el("span", "said", "→ " + t.said);
        said.title = t.said;
        item.appendChild(said);
      }
      list.appendChild(item);
    });
    if (first > 0) list.appendChild(aside("more", "+" + first + " " + T.live_earlier));
    calls[key] = work.tool_count;
    return list;
  }

  function runBlock(run) {
    var block = blockHead(run, "run");
    var meta = elapsedMeta(run);
    if (run.mode) meta.appendChild(el("span", "mode", run.mode));
    block.appendChild(meta);
    if (run.note) block.appendChild(note(run.note));
    block.appendChild(shots(run.shots));
    block.appendChild(toolList(run, "run:" + run.id));
    return keyed(block, "run:" + run.id, [run.score, run.mode, run.note, run.shots, run.tool_count, run.tools]);
  }

  function huntBlock(h) {
    var block = el("article", "run hunting");
    var head = el("header", "run-head");
    head.appendChild(el("span", "label", T.live_hunt + " " + h.id));
    var link = el("a", "hunt-mission", h.mission);
    link.href = "/hunts/" + encodeURIComponent(h.id);
    link.dir = "auto";
    head.appendChild(link);
    block.appendChild(head);
    var meta = elapsedMeta(h);
    if (h.theme) meta.appendChild(el("span", null, h.theme));
    meta.appendChild(el("span", null, h.finds + " " + T.live_finds));
    block.appendChild(meta);
    if (h.note) block.appendChild(note(h.note));
    block.appendChild(toolList(h, "hunt:" + h.id));
    return keyed(block, "hunt:" + h.id, [h.note, h.finds, h.tool_count, h.tools]);
  }

  function contactsBlock(c) {
    var block = blockHead(c, "run reading");
    var meta = el("p", "run-meta");
    meta.appendChild(el("span", "mode", T.live_contacts_mode));
    block.appendChild(meta);
    if (c.shot) block.appendChild(shot(c.shot, T.live_contacts_shot));
    block.appendChild(el("p", "live-contacts", T.live_contacts_reading));
    return keyed(block, "read:" + c.id, [c.score, c.shot]);
  }

  function timeCell(gst) {
    var time = el("span", "done-time", gst.slice(-5));
    time.title = gst + " GST";
    time.dir = "ltr";
    return time;
  }

  function nextItem(c) {  // a queued case, in the order the workers take them
    var item = el("li", "done-case");
    item.appendChild(timeCell(c.time));
    var head = el("div", "done-head");
    head.appendChild(mark(c.verdict, c.verdict_label));
    head.appendChild(el("span", "done-score", String(c.score)));
    head.appendChild(caseLink(c));
    if (c.brand) head.appendChild(el("span", "done-type", c.brand));
    item.appendChild(head);
    item.appendChild(el("p", "done-summary", c.source));
    return keyed(item, "case:" + c.id, [c.score, c.brand]);
  }

  function huntLink(h) {
    var link = el("a", "domain", h.mission);
    link.href = "/hunts/" + encodeURIComponent(h.id);
    link.dir = "auto";
    return link;
  }

  function huntItem(h) {  // a queued hunt: the workers take it before any case
    var item = el("li", "done-case");
    item.appendChild(el("span", "done-time"));
    var head = el("div", "done-head");
    head.appendChild(el("span", "label", T.live_hunt + " " + h.id));
    head.appendChild(huntLink(h));
    item.appendChild(head);
    if (h.theme) item.appendChild(el("p", "done-summary", h.theme));
    return keyed(item, "hunt:" + h.id, [h.mission, h.theme]);
  }

  function eventItem(e) {  // one entry of the "just happened" timeline
    var item = el("li", "done-case");
    item.appendChild(timeCell(e.time));
    var head = el("div", "done-head");
    head.appendChild(el("span", "label", e.label));
    if (e.kind === "hunt") {
      head.appendChild(huntLink(e));
    } else {
      head.appendChild(mark(e.verdict, e.verdict_label));
      head.appendChild(el("span", "done-score", String(e.score)));
      head.appendChild(caseLink(e));
    }
    if (e.text) head.appendChild(el("span", "done-type", e.text));
    item.appendChild(head);
    if (e.summary) {
      var summary = el("p", "done-summary", e.summary);
      summary.dir = "auto";
      item.appendChild(summary);
    }
    return keyed(item, e.key, [e.time, e.score, e.text, e.summary]);
  }

  function renderLive(a) {
    var state = live.querySelector('[data-live="state"]');
    state.className = "state " + a.state;
    state.textContent = T["live_" + a.state];
    var model = live.querySelector('[data-live="model"]');
    model.hidden = !a.model || a.state === "off";
    model.replaceChildren(el("span", "label", T.live_model), el("code", null, a.model));

    var blocks = a.hunts.map(huntBlock).concat(a.running.map(runBlock), a.contacts.reading.map(contactsBlock));
    if (a.model_down) blocks.unshift(keyed(el("p", "live-warning", T.live_waiting_note), "warning", []));
    if (!blocks.length) {
      blocks.push(keyed(el("p", "live-quiet", a.state === "idle" ? T.live_idle_note : T.live_off_note),
                        "quiet", [a.state]));
    }
    var holder = live.querySelector('[data-live="runs"]');
    patch(holder, blocks, false);
    holder.className = "runs" + (a.hunts.length + a.running.length + a.contacts.reading.length > 1 ? " parallel" : "");

    var queue = document.createDocumentFragment();
    var counts = a.queue.concat([{ label: T.live_contacts_waiting, n: a.contacts.waiting },
                                 { label: T.live_hunts_waiting, n: a.next.hunts.length }]);
    counts.forEach(function (q, i) {
      if (i >= a.queue.length && !q.n) return;
      var item = el("span", "queue-item");
      item.appendChild(el("b", null, String(q.n)));
      item.appendChild(document.createTextNode(" " + q.label));
      queue.appendChild(item);
    });
    live.querySelector('[data-live="queue"]').replaceChildren(queue);

    var next = a.next.hunts.map(huntItem).concat(a.next.cases.map(nextItem));
    if (!next.length) next.push(keyed(el("li", "live-quiet", T.live_next_none), "none", []));
    patch(live.querySelector('[data-live="next"]'), next, true);

    var events = a.events.map(eventItem);
    if (!events.length) events.push(keyed(el("li", "live-quiet", T.live_events_none), "none", []));
    patch(live.querySelector('[data-live="events"]'), events, true);
    tickElapsed();
  }

  function render(data) {
    Object.keys(data.counters).forEach(function (key) {
      var node = document.querySelector('[data-counter="' + key + '"]');
      if (node) node.textContent = data.counters[key];
    });
    ["running_since", "uptime"].forEach(function (key) {
      var node = document.querySelector('[data-field="' + key + '"]');
      if (node && data[key]) node.textContent = data[key];
    });
    var rows = document.createDocumentFragment();
    data.rows.forEach(function (r) { rows.appendChild(row(r)); });
    if (!data.rows.length) {
      var tr = el("tr", "empty");
      var td = cell(body.getAttribute("data-empty"));
      td.colSpan = 7;
      tr.appendChild(td);
      rows.appendChild(tr);
    }
    body.replaceChildren(rows);
    data.rows.forEach(function (r) { seen[r.id] = true; });
    renderLive(data.activity);
    renderWatch(data.maps);
  }

  // Google Maps watch: the searches of the last round as a log and, with a
  // browser key, on a Google map that moves to each search as its answer arrives.

  var part = {};
  ["state", "query", "wait", "now", "meta", "off", "split", "map-col", "map", "map-note", "log"].forEach(function (k) {
    part[k] = watch.querySelector('[data-mw="' + k + '"]');
  });
  var NOW_LABEL = part.now.textContent;
  // Quiet greyscale in the dashboard's paper and ink; no points of interest, so only Shaheen's marks show.
  var MAP_STYLES = [
    { elementType: "geometry", stylers: [{ color: "#f0eee9" }] },
    { elementType: "labels.icon", stylers: [{ visibility: "off" }] },
    { elementType: "labels.text.fill", stylers: [{ color: "#67625b" }] },
    { elementType: "labels.text.stroke", stylers: [{ color: "#fbfaf7" }] },
    { featureType: "administrative", elementType: "geometry.stroke", stylers: [{ color: "#9f9b94" }] },
    { featureType: "poi", stylers: [{ visibility: "off" }] },
    { featureType: "transit", stylers: [{ visibility: "off" }] },
    { featureType: "road", elementType: "geometry", stylers: [{ color: "#fbfaf7" }] },
    { featureType: "road.highway", elementType: "geometry", stylers: [{ color: "#e3ded4" }] },
    { featureType: "road", elementType: "labels.text.fill", stylers: [{ color: "#9f9b94" }] },
    { featureType: "water", elementType: "geometry", stylers: [{ color: "#d9d6d0" }] },
    { featureType: "water", elementType: "labels.text.fill", stylers: [{ color: "#9f9b94" }] }
  ];
  var DRAW_ORDER = { other: 0, brand_ok: 1, lead: 2 };  // leads drawn last, on top
  var mapState = watch.hasAttribute("data-key") ? "unloaded" : "no_key";  // then loading, ready, failed or refused
  var gmap = null;
  var api = null;  // the Google classes the map uses, once loaded
  var marks = null;  // the overlay of the search on the map
  var shown = null;  // which searches are on the map, and which one is in focus
  var latest = null;  // the last maps object, drawn once the map is ready
  var pressing = false;

  function loadMap() {
    mapState = "loading";
    window.shaheenMapReady = function () {
      Promise.all([google.maps.importLibrary("maps"), google.maps.importLibrary("core")])
        .then(function (libs) { createMap(libs[0], libs[1]); })
        .catch(function () { mapFailed("failed"); });
    };
    window.gm_authFailure = function () { mapFailed("refused"); };
    var params = new URLSearchParams({
      key: watch.getAttribute("data-key"), loading: "async", callback: "shaheenMapReady",
      language: watch.getAttribute("data-lang")
    });
    var script = document.createElement("script");
    script.src = "https://maps.googleapis.com/maps/api/js?" + params.toString();
    script.async = true;
    if (NONCE) script.nonce = NONCE;
    script.onerror = function () { mapFailed("failed"); };
    document.head.appendChild(script);
  }

  function marksClass(OverlayView, LatLng) {
    // Fixed-size marks in a custom overlay: no Map ID needed and none of the deprecated Marker class.
    return class extends OverlayView {
      constructor(items) {  // {listing, past}: past marks belong to an earlier search of the round under way
        super();
        this.items = items;
        this.nodes = [];
      }
      onAdd() {
        var pane = this.getPanes().overlayMouseTarget;
        this.nodes = this.items.map(function (item) {
          var node = el("span", "pin " + item.listing.outcome + (item.past ? " past" : ""));
          node.title = item.listing.name;
          pane.appendChild(node);
          return node;
        });
      }
      draw() {
        var projection = this.getProjection();
        this.items.forEach(function (item, i) {
          var point = projection.fromLatLngToDivPixel(new LatLng(item.listing.lat, item.listing.lng));
          this.nodes[i].style.left = point.x + "px";
          this.nodes[i].style.top = point.y + "px";
        }, this);
      }
      onRemove() {
        this.nodes.forEach(function (node) { node.remove(); });
        this.nodes = [];
      }
    };
  }

  function createMap(mapsLib, core) {
    gmap = new mapsLib.Map(part.map, {
      center: { lat: 24.6, lng: 54.7 }, zoom: 7, styles: MAP_STYLES, backgroundColor: "#f0eee9",
      disableDefaultUI: true, zoomControl: true, clickableIcons: false, gestureHandling: "cooperative"
    });
    api = { Marks: marksClass(mapsLib.OverlayView, core.LatLng), LatLngBounds: core.LatLngBounds, event: core.event };
    mapState = "ready";
    if (latest) renderWatch(latest);
  }

  function mapFailed(reason) {
    mapState = reason;
    if (latest) renderWatch(latest);
  }

  function drawSearch(m) {
    // Every listing of the searches kept. While a round runs, the newest answered search
    // is in focus and framed, and the earlier ones are dimmed; when idle, the whole round.
    var done = m.searches.filter(function (s) { return s.state === "done"; });
    var focus = m.state === "searching" && done.length ? done[done.length - 1] : null;
    var key = done.map(function (s) { return s.time + " " + s.query; }).join("|") + (focus ? " (focus)" : "");
    if (key === shown) return;
    shown = key;
    if (marks) marks.setMap(null);
    marks = null;
    var items = [];
    done.forEach(function (s) {
      s.listings.forEach(function (l) {
        if (l.lat !== null && l.lng !== null) items.push({ listing: l, past: focus !== null && s !== focus });
      });
    });
    if (!items.length) return;
    items.sort(function (a, b) {
      return (b.past - a.past) || DRAW_ORDER[a.listing.outcome] - DRAW_ORDER[b.listing.outcome];
    });
    marks = new api.Marks(items);
    marks.setMap(gmap);
    var framed = items.filter(function (item) { return !item.past; });
    var located = (framed.length ? framed : items).map(function (item) { return item.listing; });
    if (located.length === 1) {
      gmap.panTo({ lat: located[0].lat, lng: located[0].lng });
      gmap.setZoom(13);
    } else {
      var bounds = new api.LatLngBounds();
      located.forEach(function (l) { bounds.extend({ lat: l.lat, lng: l.lng }); });
      gmap.fitBounds(bounds, 56);
      api.event.addListenerOnce(gmap, "idle", function () {
        if (gmap.getZoom() > 14) gmap.setZoom(14);
      });
    }
  }

  function query(text, language) {
    var node = el("bdi", "mw-q", text);
    node.dir = language === "ar" ? "rtl" : "ltr";
    node.lang = language;
    return node;
  }

  function clockOf(gst) {  // "YYYY-MM-DD HH:MM" shown as HH:MM, the full time on hover
    var node = el("bdi", null, gst.slice(-5));
    node.dir = "ltr";
    node.title = gst + " GST";
    return node;
  }

  function leadLine(l) {
    var line = el("span", "listing mw-lead");
    var link = el("a", null, l.name);
    link.href = "/maps";
    link.title = T.maps;
    link.dir = "auto";
    line.appendChild(link);
    [[l.website, T.maps_kind_website], [l.phone, T.maps_kind_helpline]].forEach(function (pair) {
      if (!pair[0]) return;
      line.appendChild(el("span", "mw-kind", pair[1]));
      var value = el("bdi", "mono", pair[0]);
      value.dir = "ltr";
      line.appendChild(value);
    });
    return line;
  }

  function searchRow(s) {
    var tr = el("tr", s.current ? "current" : null);
    var time = cell("", "time");
    var at = el("bdi", null, s.time);
    at.dir = "ltr";
    time.appendChild(at);
    tr.appendChild(time);
    var what = cell("");
    what.appendChild(query(s.query, s.language));
    s.listings.forEach(function (l) { if (l.outcome === "lead") what.appendChild(leadLine(l)); });
    tr.appendChild(what);
    if (s.state === "pending") {
      tr.appendChild(cell(T.mw_pending, "num muted"));
      tr.appendChild(cell("", "num"));
    } else if (s.state === "failed") {
      var failed = cell("", "num");
      failed.appendChild(el("span", "stamp dashed", T.mw_failed));
      tr.appendChild(failed);
      tr.appendChild(cell("", "num"));
    } else {
      tr.appendChild(cell(String(s.count), "num"));
      tr.appendChild(cell(String(s.leads), "num" + (s.leads ? " hit" : "")));
    }
    return tr;
  }

  function metaItem(label, value) {
    var item = el("span", null);
    item.appendChild(el("span", "label", label));
    item.appendChild(value);
    return item;
  }

  function renderWatch(m) {
    latest = m;
    part.state.className = "state " + (m.state === "searching" ? "running" : m.state);
    part.state.textContent = m.state === "searching" ? T.mw_searching : m.state === "idle" ? T.live_idle : T.live_off;
    part.query.replaceChildren();
    if (m.query) part.query.appendChild(query(m.query, m.language));

    part.now.hidden = m.state === "off";
    part.now.disabled = pressing || !m.can_search;
    part.now.textContent = pressing ? part.now.getAttribute("data-busy") : NOW_LABEL;
    part.wait.replaceChildren();
    if (m.state === "searching") part.wait.textContent = T.mw_busy;
    else if (m.state === "idle" && m.next_allowed) {
      part.wait.append(T.mw_next_allowed + " ", clockOf(m.next_allowed));
    }

    var meta = document.createDocumentFragment();
    if (m.last_run) meta.appendChild(metaItem(T.mw_last_round, clockOf(m.last_run)));
    if (m.state !== "off") {
      meta.appendChild(metaItem(T.mw_next_round, m.next_run ? clockOf(m.next_run) : el("span", null, T.mw_due)));
    }
    meta.appendChild(metaItem(T.mw_calls_today, el("b", null, String(m.calls_today))));
    part.meta.replaceChildren(meta);

    part.off.hidden = m.state !== "off";
    part.off.textContent = m.off === "no_key" ? T.maps_off : T.mw_off_elsewhere;
    part.split.hidden = m.state === "off";
    if (m.state === "off") return;

    if (mapState === "unloaded") loadMap();
    var withMap = mapState === "loading" || mapState === "ready";
    part["map-col"].hidden = !withMap;
    part.split.className = "mw-split" + (withMap ? "" : " log-only");
    part["map-note"].hidden = withMap;
    part["map-note"].textContent = withMap ? "" : T["mw_map_" + mapState];
    if (mapState === "ready") drawSearch(m);

    var rows = document.createDocumentFragment();
    m.searches.forEach(function (s) { rows.appendChild(searchRow(s)); });
    if (!m.searches.length) {
      var empty = cell(T.mw_none, "muted");
      empty.colSpan = 4;
      rows.appendChild(el("tr", "empty")).appendChild(empty);
    }
    part.log.replaceChildren(rows);
  }

  part.now.addEventListener("click", function () {
    pressing = true;
    part.now.disabled = true;
    part.now.textContent = part.now.getAttribute("data-busy");
    fetch("/maps/search", { method: "POST", credentials: "same-origin" })
      .catch(function () {})
      .then(function () {
        pressing = false;
        refresh();
      });
  });

  var timer = null;
  var pushed = 0;  // when the stream last delivered

  function schedule(data) {
    clearTimeout(timer);
    timer = setTimeout(refresh, data && data.maps.state === "searching" ? 2000 : 5000);
  }

  function refresh() {
    if (Date.now() - pushed < 10000) {
      schedule(null);
      return;
    }
    fetch("/api/feed" + window.location.search, { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) {
        if (data) render(data);
        schedule(data);
      })
      .catch(function () { schedule(null); });
  }

  if (window.EventSource) {
    new EventSource("/api/feed/stream" + window.location.search).onmessage = function (event) {
      pushed = Date.now();
      render(JSON.parse(event.data));
    };
  }
  refresh();
  setInterval(tickElapsed, 1000);

  var form = document.getElementById("scan-form");
  if (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector("button");
      button.disabled = true;
      button.textContent = button.getAttribute("data-busy");
    });
  }
})();
