// backtide · the theme, set before the page paints (this file loads without defer, in <head>).
// The page follows the system (prefers-color-scheme, in web.css) unless the person chose with
// the switch, which web.js remembers in local storage. No inline script: the CSP forbids it.
(function () {
  "use strict";
  try {
    var saved = window.localStorage.getItem("backtide-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch (ignored) {
    // no storage (a private window may refuse it): the system's theme it is
  }
})();
