// Live feed: refresh the counters, the latest scans and the AI investigator
// panel every 5 seconds from /api/feed. Everything is built with textContent
// only, never innerHTML; addresses arrive defanged from the server.
(function () {
  "use strict";
  var VERDICTS = ["fraud", "suspicious", "legitimate"];
  var T = JSON.parse(document.getElementById("strings").textContent);
  var body = document.getElementById("feed-rows");
  var live = document.getElementById("live");
  var seen = {};
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

  function badge(verdict, label) {
    return el("span", "badge " + (VERDICTS.indexOf(verdict) >= 0 ? verdict : ""), label);
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
    tr.appendChild(cell(r.time, "nowrap"));
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
    verdict.appendChild(badge(r.verdict, r.verdict_label));
    tr.appendChild(verdict);
    tr.appendChild(cell(String(r.score), "num"));
    tr.appendChild(cell(r.type));
    tr.appendChild(cell(r.brand));
    tr.appendChild(cell(r.source, "muted"));
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

  function runBlock(run) {
    var block = el("article", "live-run");
    block.setAttribute("data-id", run.id);
    var head = el("header", "live-run-head");
    head.appendChild(badge(run.verdict, run.verdict_label));
    head.appendChild(el("span", "num score", String(run.score)));
    head.appendChild(caseLink(run));
    var elapsed = el("span", "elapsed muted");
    elapsed.setAttribute("data-started", String(Date.now() - run.elapsed_s * 1000));
    head.appendChild(elapsed);
    head.appendChild(el("span", "muted", T.live_calls + ": " + run.tool_count));
    if (run.mode) head.appendChild(el("span", "pill", run.mode));
    block.appendChild(head);

    var list = el("ol", "live-tools");
    list.dir = "ltr";
    var hidden = run.tool_count - run.tools.length;
    if (hidden > 0) list.appendChild(el("li", "more muted", "+" + hidden + " " + T.live_earlier));
    run.tools.forEach(function (t) {
      var item = el("li", "call " + (t.error ? "error" : t.done ? "done" : "running"));
      if (t.server) item.appendChild(el("span", "server", t.server));
      item.appendChild(el("code", "tool", t.tool));
      if (t.target) item.appendChild(el("span", "target mono", t.target));
      list.appendChild(item);
    });
    var last = run.tools[run.tools.length - 1];
    if (!last) list.appendChild(el("li", "note muted", T.live_starting));
    else if (last.done) list.appendChild(el("li", "note muted", T.live_thinking));
    block.appendChild(list);
    return block;
  }

  function recentItem(r) {
    var item = el("li", "live-done");
    var head = el("div", "live-done-head");
    head.appendChild(caseLink(r));
    if (r.type) head.appendChild(el("span", "type", r.type));
    item.appendChild(head);
    if (r.summary) {
      var summary = el("p", "summary small", r.summary);
      summary.dir = "auto";
      item.appendChild(summary);
    }
    return item;
  }

  function renderLive(a) {
    var state = live.querySelector('[data-live="state"]');
    state.className = "pill live-state " + a.state;
    state.textContent = T["live_" + a.state];
    var model = live.querySelector('[data-live="model"]');
    model.hidden = !a.model || a.state === "off";
    model.textContent = T.live_model + ": " + a.model;

    var runs = document.createDocumentFragment();
    if (a.model_down) runs.appendChild(el("p", "live-warning", T.live_waiting_note));
    a.running.forEach(function (run) { runs.appendChild(runBlock(run)); });
    if (!a.running.length && !a.model_down) {
      runs.appendChild(el("p", "muted", a.state === "idle" ? T.live_idle_note : T.live_off_note));
    }
    live.querySelector('[data-live="runs"]').replaceChildren(runs);

    live.querySelector('[data-live="queue"]').textContent = a.queue.map(function (q) {
      return q.label + " " + q.n;
    }).join(" · ");

    var recent = document.createDocumentFragment();
    a.recent.forEach(function (r) { recent.appendChild(recentItem(r)); });
    if (!a.recent.length) recent.appendChild(el("li", "muted", T.live_no_recent));
    live.querySelector('[data-live="recent"]').replaceChildren(recent);
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
  }

  function refresh() {
    fetch("/api/feed" + window.location.search, { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) { if (data) render(data); })
      .catch(function () {});
  }

  refresh();
  setInterval(refresh, 5000);
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
