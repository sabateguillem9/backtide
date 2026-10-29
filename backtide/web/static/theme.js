// backtide · the theme, set before the page paints (this file loads without defer, in <head>).
// The page follows the system (<html data-theme="auto">: tokens.css turns dark with
// prefers-color-scheme) unless the person chose with the switch, which web.js remembers in local
// storage, and only there. No inline script: the CSP forbids it.
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
  // A page transition the browser skips (a fast second click, a page that arrives hidden) is not
  // an error worth a console line. Here, not in the deferred web.js: pagereveal fires before it.
  function quiet(event) {
    var transition = event.viewTransition;
    if (!transition) return;
    ["ready", "finished", "updateCallbackDone"].forEach(function (name) {
      if (transition[name] && transition[name].catch) transition[name].catch(function () {});
    });
  }
  window.addEventListener("pagereveal", quiet);
  window.addEventListener("pageswap", quiet);
})();
