/* backtide · idle drawings (D34), for the public site only, with motion/idle.css. Load it at
   the end of <body>, after motion/motion.js. The product web never loads either file.

   Opt in with data-idle on a container (every drawing inside it; data-idle="off" rests them
   again) or .ic--idle on one drawing. This file gives each of those drawings:
   - .ic--phase-0 ... -6, once, so drawings side by side never move together;
   - .ic--idling, only while it is on screen (IntersectionObserver). idle.css needs it.
   Drawings that scripts build or rebuild later (a language change) are picked up as they come.
   Nothing idles with reduced motion, without IntersectionObserver or without JavaScript, and
   motion.css pauses everything while the tab is hidden. No storage; classes only, never markup. */
(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (root.classList.contains("still") || reduce.matches || !("IntersectionObserver" in window)) return;

  var PHASES = 7;
  var count = 0;
  var watched = [];
  var stopped = false;
  var io = new IntersectionObserver(function (list) {
    list.forEach(function (e) { e.target.classList.toggle("ic--idling", e.isIntersecting); });
  });

  function wanted(svg) {
    if (svg.classList.contains("ic--idle")) return true;
    var box = svg.closest("[data-idle]");
    return Boolean(box) && box.getAttribute("data-idle") !== "off";
  }

  function rest(svg) {
    io.unobserve(svg);
    svg.classList.remove("ic--idling");
  }

  function scan() {
    if (stopped) return;
    watched = watched.filter(function (svg) {
      if (svg.isConnected && wanted(svg)) return true;
      rest(svg);
      return false;
    });
    Array.prototype.forEach.call(document.querySelectorAll("svg.ic"), function (svg) {
      if (watched.indexOf(svg) >= 0 || !wanted(svg)) return;
      if (!/\bic--phase-\d\b/.test(svg.getAttribute("class") || "")) {
        svg.classList.add("ic--phase-" + (count++ % PHASES));
      }
      watched.push(svg);
      io.observe(svg);
    });
  }

  var queued = false;
  new MutationObserver(function () {
    if (queued) return;
    queued = true;
    requestAnimationFrame(function () { queued = false; scan(); });
  }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["data-idle"] });

  // Reduced motion switched on while the page is open: everything rests for good.
  if (reduce.addEventListener) {
    reduce.addEventListener("change", function () {
      if (!reduce.matches) return;
      stopped = true;
      watched.forEach(rest);
      watched = [];
      io.disconnect();
    });
  }

  scan();
  window.BacktideIdle = { scan: scan };
})();
