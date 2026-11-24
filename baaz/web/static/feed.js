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

  function aside(cls, text) {  // a line of prose in the LTR log, in the page's language
    var item = el("li", cls, text);
    item.dir = "auto";
    return item;
  }

  function runBlock(run) {
    var block = el("article", "run");
    block.setAttribute("data-id", run.id);
    var head = el("header", "run-head");
    head.appendChild(mark(run.verdict, run.verdict_label));
    head.appendChild(el("span", "run-score", String(run.score)));
    head.appendChild(caseLink(run));
    block.appendChild(head);

    var meta = el("p", "run-meta");
    var elapsed = el("span", "elapsed");
    elapsed.setAttribute("data-started", String(Date.now() - run.elapsed_s * 1000));
    meta.appendChild(elapsed);
    meta.appendChild(el("span", null, T.live_calls + " " + run.tool_count));
    if (run.mode) meta.appendChild(el("span", "mode", run.mode));
    block.appendChild(meta);

    var list = el("ol", "log-tail");
    list.dir = "ltr";
    var first = run.tool_count - run.tools.length;
    var known = calls[run.id];
    if (first > 0) list.appendChild(aside("more", "+" + first + " " + T.live_earlier));
    run.tools.forEach(function (t, i) {
      var n = first + i + 1;
      var cls = "call " + (t.error ? "err" : t.done ? "done" : "running");
      if (i === run.tools.length - 1) cls += " latest";
      if (known !== undefined && n > known) cls += " fresh";
      var item = el("li", cls);
      item.appendChild(el("span", "n", String(n).padStart(2, "0")));
      item.appendChild(el("span", "server", t.server));
      item.appendChild(el("code", "tool", t.tool));
      var target = el("span", "target", t.target);
      target.title = t.target;
      item.appendChild(target);
      if (t.error) item.appendChild(el("span", "stamp dashed", T.error));
      list.appendChild(item);
    });
    calls[run.id] = run.tool_count;
    var last = run.tools[run.tools.length - 1];
    if (!last) list.appendChild(aside("note", T.live_starting));
    else if (last.done) list.appendChild(aside("note", T.live_thinking));
    block.appendChild(list);
    return block;
  }

  function recentItem(r) {
    var item = el("li", "done-case");
    var time = el("span", "done-time", r.time.slice(-5));
    time.title = r.time;
    time.dir = "ltr";
    item.appendChild(time);
    var head = el("div", "done-head");
    head.appendChild(mark(r.verdict, r.verdict_label));
    head.appendChild(el("span", "done-score", String(r.score)));
    head.appendChild(caseLink(r));
    if (r.type) head.appendChild(el("span", "done-type", r.type));
    item.appendChild(head);
    if (r.summary) {
      var summary = el("p", "done-summary", r.summary);
      summary.dir = "auto";
      item.appendChild(summary);
    }
    return item;
  }

  function renderLive(a) {
    var state = live.querySelector('[data-live="state"]');
    state.className = "state " + a.state;
    state.textContent = T["live_" + a.state];
    var model = live.querySelector('[data-live="model"]');
    model.hidden = !a.model || a.state === "off";
    model.replaceChildren(el("span", "label", T.live_model), el("code", null, a.model));

    var runs = document.createDocumentFragment();
    if (a.model_down) runs.appendChild(el("p", "live-warning", T.live_waiting_note));
    a.running.forEach(function (run) { runs.appendChild(runBlock(run)); });
    if (!a.running.length && !a.model_down) {
      runs.appendChild(el("p", "live-quiet", a.state === "idle" ? T.live_idle_note : T.live_off_note));
    }
    var holder = live.querySelector('[data-live="runs"]');
    holder.replaceChildren(runs);
    holder.className = "runs" + (a.running.length > 1 ? " parallel" : "");

    var queue = document.createDocumentFragment();
    a.queue.forEach(function (q) {
      var item = el("span", "queue-item");
      item.appendChild(el("b", null, String(q.n)));
      item.appendChild(document.createTextNode(" " + q.label));
      queue.appendChild(item);
    });
    live.querySelector('[data-live="queue"]').replaceChildren(queue);

    var recent = document.createDocumentFragment();
    a.recent.forEach(function (r) { recent.appendChild(recentItem(r)); });
    if (!a.recent.length) recent.appendChild(el("li", "live-quiet", T.live_no_recent));
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
