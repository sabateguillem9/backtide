/* backtide · the line boil, for the public site only (approved by the founder, 2026-10-30). Load
   it at the end of <body>, after icons/icons.js and motion/idle.js. The product web never loads it.

   A drawing by the field hand (icons/hand.py) comes with three frames of each line: the still
   drawing and two that only tremble differently. While a drawing boils, this file swaps its
   paths' d from one frame to the next every duration-boil (280 ms, about 3.6 a second), stepped
   and never tweened, so the line seems drawn again and again, like hand-drawn animation.

   A drawing boils:
   - while it idles (idle.js gives it .ic--idling only while it is opted in and on screen);
   - while its .ic-host is pointed at or has keyboard focus (any drawing on the site).
   When it stops it goes back to frame 0, the still drawing, the one written in the page.
   data-boil="off" on a drawing or a container keeps those drawings still.

   Never with prefers-reduced-motion (nor .still), never while the tab is hidden, never without
   JavaScript (the page then shows frame 0, which is the markup). Only the d attribute of the
   drawings' own paths changes; no markup, no style, no storage.
   window.BacktideBoil.stop() rests every drawing and stops; .start() starts again (if allowed). */
(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  var icons = window.BacktideIcons;
  if (!icons || !icons.frames) return;

  var ms = parseFloat(getComputedStyle(root).getPropertyValue("--duration-boil")) || 280;
  var ACTIVE = "svg.ic.ic--idling, .ic-host:hover svg.ic, .ic-host:focus-visible svg.ic";
  var timer = 0;
  var tick = 0;
  var on = true;
  var boiling = [];

  function allowed() {
    return on && !reduce.matches && !root.classList.contains("still") && !document.hidden;
  }

  function nameOf(svg) {
    var m = /(?:^|\s)ic-([a-z][\w-]*)/.exec(svg.getAttribute("class") || "");
    return m ? m[1] : "";
  }

  function show(svg, k) {
    var frames = icons.frames(nameOf(svg));
    if (!frames) return false;
    var paths = svg.querySelectorAll("path");
    if (paths.length !== frames.length) return false;
    for (var i = 0; i < paths.length; i++) {
      var d = frames[i][k % frames[i].length];
      if (paths[i].getAttribute("d") !== d) paths[i].setAttribute("d", d);
    }
    return true;
  }

  function rest() {
    boiling.forEach(function (svg) { show(svg, 0); });
    boiling = [];
  }

  function step() {
    timer = 0;
    if (!allowed()) { rest(); return; }
    tick += 1;
    var now = Array.prototype.filter.call(document.querySelectorAll(ACTIVE), function (svg) {
      return !svg.closest('[data-boil="off"]');
    });
    boiling.forEach(function (svg) { if (now.indexOf(svg) < 0) show(svg, 0); });
    boiling = now.filter(function (svg) { return show(svg, tick); });
    timer = window.setTimeout(step, ms);
  }

  function start() {
    on = true;
    if (!timer && allowed()) timer = window.setTimeout(step, ms);
  }

  function stop() {
    on = false;
    if (timer) window.clearTimeout(timer);
    timer = 0;
    rest();
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      if (timer) window.clearTimeout(timer);
      timer = 0;
      rest();
    } else if (on) {
      start();
    }
  });
  if (reduce.addEventListener) {
    reduce.addEventListener("change", function () { if (reduce.matches) stop(); });
  }

  window.BacktideBoil = { start: start, stop: stop };
  start();
})();
