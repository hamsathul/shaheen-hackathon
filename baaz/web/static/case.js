// Live trace: while this case's investigation is queued or running, fetch
// /api/case/<id>/live every 5 seconds and redraw the tool-call trace. Once the
// run's record is filed, load the page again to show the report. Everything
// is built with textContent only; the server sends it defanged.
(function () {
  "use strict";
  var section = document.getElementById("trace");
  var status = section ? section.getAttribute("data-status") : "";
  if (status !== "running" && status !== "queued") return;
  var T = JSON.parse(document.getElementById("strings").textContent);
  var id = section.getAttribute("data-case");

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function step(s) {
    if (s.kind === "model") {
      var said = el("li", "step model");
      said.appendChild(el("div", "who", T.model));
      var text = el("p", null, s.text);
      text.dir = "auto";
      said.appendChild(text);
      return said;
    }
    var item = el("li", "step tool" + (s.error ? " err" : s.done ? "" : " running"));
    var call = el("div", "call");
    if (s.server) call.appendChild(el("span", "server", s.server));
    call.appendChild(el("code", "tool", s.tool));
    call.appendChild(el("code", "args", s.args));
    if (s.ms !== null) call.appendChild(el("span", "ms", s.ms + " ms"));
    if (!s.done) call.appendChild(el("span", "pill", T.live_running));
    if (s.error) call.appendChild(el("span", "pill danger", T.error));
    item.appendChild(call);
    if (s.result) item.appendChild(el("pre", "result", s.result));
    return item;
  }

  function render(steps) {
    var list = el("ol", "timeline");
    list.dir = "ltr";
    steps.forEach(function (s) { list.appendChild(step(s)); });
    var old = section.querySelector(".timeline, .no-trace");
    if (old) old.replaceWith(list);
    else section.appendChild(list);
  }

  function poll() {
    fetch("/api/case/" + encodeURIComponent(id) + "/live", { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) {
        if (!data) return;
        if (data.filed) {
          window.location.replace("/case/" + encodeURIComponent(id));
          return;
        }
        if (data.steps.length) render(data.steps);
      })
      .catch(function () {});
  }

  poll();
  setInterval(poll, 5000);
})();
