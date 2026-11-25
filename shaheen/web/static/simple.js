// Simple feed: refresh the headline numbers, the AI and Maps lines, what the AI
// is doing now and the two lists of sites from /api/feed every 5 seconds. Everything is built with
// textContent only, never innerHTML; addresses arrive defanged from the server.
(function () {
  "use strict";
  var root = document.getElementById("simple");
  var seen = {};
  Array.prototype.forEach.call(root.querySelectorAll(".site[data-id]"), function (item) {
    seen[item.getAttribute("data-id")] = true;
  });

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function part(name) {
    return root.querySelector('[data-simple="' + name + '"]');
  }

  function said(lang, text) {
    var line = el("p", null, text);
    line.lang = lang;
    line.dir = lang === "ar" ? "rtl" : "ltr";
    return line;
  }

  function site(r) {
    var item = el("li", "site" + (seen[r.id] ? "" : " fresh"));
    item.setAttribute("data-id", r.id);
    var when = el("p", "site-when");
    when.dir = "ltr";
    when.append(el("span", null, r.time), r.date);
    item.appendChild(when);
    var head = el("div", "site-head");
    head.appendChild(el("span", "mark " + r.verdict, r.label));
    var link = el("a", "site-domain", r.domain);
    link.href = "/case/" + encodeURIComponent(r.id);
    link.dir = "ltr";
    head.appendChild(link);
    item.appendChild(head);
    if (r.brand || r.kind) {
      var what = el("p", "site-what");
      if (r.brand) what.appendChild(el("b", null, r.brand));
      if (r.kind) what.appendChild(el("span", null, r.kind));
      item.appendChild(what);
    }
    var say = el("div", "site-say");
    say.append(said("en", r.en), said("ar", r.ar));
    item.appendChild(say);
    return item;
  }

  function liveItem(w) {  // a site the AI is checking or reading, or a hunt, with its screenshot
    var item = el("figure", "simple-live-item");
    if (w.shot) {
      var img = el("img");
      img.src = w.shot;
      img.alt = "";
      item.appendChild(img);
    }
    var caption = el("figcaption", null, w.label + " ");
    var link = el("a", null, w.subject);
    link.href = w.href;
    link.dir = "auto";
    caption.appendChild(link);
    item.appendChild(caption);
    return item;
  }

  function renderLive(work) {
    var holder = part("live");
    var shown = JSON.stringify(work);
    if (holder.getAttribute("data-sig") === shown) return;  // unchanged: keep the images as they are
    holder.setAttribute("data-sig", shown);
    holder.replaceChildren.apply(holder, work.map(liveItem));
  }

  function renderList(verdict, found) {
    var list = part(verdict);
    var items = document.createDocumentFragment();
    found.rows.forEach(function (r) { items.appendChild(site(r)); });
    if (!found.rows.length) items.appendChild(el("li", "site-none", list.getAttribute("data-empty")));
    list.replaceChildren(items);
    part(verdict + "-count").textContent = found.count;
  }

  function render(data) {
    Object.keys(data.counters).forEach(function (key) {
      var node = root.querySelector('[data-counter="' + key + '"]');
      if (node) node.textContent = data.counters[key];
    });
    ["running_since", "uptime"].forEach(function (key) {
      var node = document.querySelector('[data-field="' + key + '"]');
      if (node && data[key]) node.textContent = data[key];
    });
    var s = data.simple;
    part("suspicious-total").textContent = s.suspicious_total;
    part("ai").textContent = s.ai;
    renderLive(s.live);
    part("maps").textContent = s.maps;
    ["fraud", "suspicious"].forEach(function (verdict) {
      renderList(verdict, s[verdict]);
      s[verdict].rows.forEach(function (r) { seen[r.id] = true; });
    });
  }

  function refresh() {
    fetch("/api/feed", { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) { if (data && data.simple) render(data); })
      .catch(function () {})
      .then(function () { setTimeout(refresh, 5000); });
  }

  refresh();  // at once: the page arrives without the live line, which only this draws

  var form = document.getElementById("scan-form");
  form.addEventListener("submit", function () {
    var button = form.querySelector("button");
    button.disabled = true;
    button.textContent = button.getAttribute("data-busy");
  });
})();
