// Statistics: every 60 seconds, load this page again and swap in its charts,
// which the server draws. The scroll position stays, and so does any table the
// reader opened. The new nodes come parsed from the server's own escaped HTML.
(function () {
  "use strict";

  function refresh() {
    fetch(window.location.pathname, { credentials: "same-origin" })
      .then(function (resp) { return resp.ok ? resp.text() : null; })
      .then(function (html) {
        var current = document.getElementById("stats");
        var fresh = html && new DOMParser().parseFromString(html, "text/html").getElementById("stats");
        if (!fresh) return;
        var open = Array.prototype.map.call(current.querySelectorAll("details"), function (d) { return d.open; });
        fresh = document.importNode(fresh, true);
        Array.prototype.forEach.call(fresh.querySelectorAll("details"), function (d, i) { d.open = !!open[i]; });
        current.replaceWith(fresh);
      })
      .catch(function () {});
  }

  setInterval(refresh, 60000);
})();
