// Live feed: refresh the counters and the latest scans every 5 seconds from
// /api/feed. Rows are built with textContent only, never innerHTML.
(function () {
  "use strict";
  var VERDICTS = ["fraud", "suspicious", "legitimate"];
  var body = document.getElementById("feed-rows");
  var seen = {};
  Array.prototype.forEach.call(body.querySelectorAll("tr[data-id]"), function (tr) {
    seen[tr.getAttribute("data-id")] = true;
  });

  function cell(text, cls) {
    var td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = text;
    return td;
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
    if (r.confirmed) {
      var tick = document.createElement("span");
      tick.className = "tick";
      tick.textContent = " ✓";
      domain.appendChild(tick);
    }
    tr.appendChild(domain);
    var verdict = cell("");
    var badge = document.createElement("span");
    badge.className = "badge " + (VERDICTS.indexOf(r.verdict) >= 0 ? r.verdict : "");
    badge.textContent = r.verdict_label;
    verdict.appendChild(badge);
    tr.appendChild(verdict);
    tr.appendChild(cell(String(r.score), "num"));
    tr.appendChild(cell(r.type));
    tr.appendChild(cell(r.brand));
    tr.appendChild(cell(r.source, "muted"));
    return tr;
  }

  function render(data) {
    Object.keys(data.counters).forEach(function (key) {
      var el = document.querySelector('[data-counter="' + key + '"]');
      if (el) el.textContent = data.counters[key];
    });
    ["running_since", "uptime"].forEach(function (key) {
      var el = document.querySelector('[data-field="' + key + '"]');
      if (el && data[key]) el.textContent = data[key];
    });
    var rows = document.createDocumentFragment();
    data.rows.forEach(function (r) { rows.appendChild(row(r)); });
    if (!data.rows.length) {
      var tr = document.createElement("tr");
      tr.className = "empty";
      var td = cell(body.getAttribute("data-empty"));
      td.colSpan = 7;
      tr.appendChild(td);
      rows.appendChild(tr);
    }
    body.replaceChildren(rows);
    data.rows.forEach(function (r) { seen[r.id] = true; });
  }

  function refresh() {
    fetch("/api/feed" + window.location.search, { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) { if (data) render(data); })
      .catch(function () {});
  }

  setInterval(refresh, 5000);

  var form = document.getElementById("scan-form");
  if (form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector("button");
      button.disabled = true;
      button.textContent = button.getAttribute("data-busy");
    });
  }
})();
