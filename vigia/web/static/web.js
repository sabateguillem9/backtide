// backtide · lookout post. The only script of ours: keep the conversation in view and clear the
// question box. Everything else is HTMX (vendored in vendor/). No inline scripts: see the CSP.
(function () {
  "use strict";
  var stick = true;

  function atBottom() {
    return window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 160;
  }
  function toBottom() {
    window.scrollTo(0, document.documentElement.scrollHeight);
  }

  document.body.addEventListener("htmx:sseBeforeMessage", function () {
    stick = atBottom();
  });
  document.body.addEventListener("htmx:sseMessage", function () {
    if (stick) toBottom();
  });
  document.body.addEventListener("htmx:afterRequest", function (event) {
    var form = event.target;
    if (form && form.classList && form.classList.contains("ask") && event.detail.successful) {
      form.reset();
      toBottom();
    }
  });
  if (document.getElementById("feed")) {
    window.addEventListener("load", toBottom);
  }
})();
