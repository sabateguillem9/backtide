/* backtide · motion helpers. Load at the end of <body>, after motion/boot.js ran in <head>.
   No dependencies and no storage. It never writes markup: classes only.

   - Reveal on scroll, once: [data-reveal="rise"], "line", "rise line" or "draw". Only what
     lies below the fold at load is hidden first, so nothing painted is ever faded out.
     Children of [data-reveal-group] are staggered (.d-0 ... .d-5, 80 ms apart).
   - Inside the box: [data-layers] plays when a third of it is on screen.
   - Nothing moves while the tab is hidden (.is-hidden on <html>).
   - BacktideMotion.swap(fn): runs fn inside a view transition when motion is allowed. */
(function () {
  "use strict";
  var root = document.documentElement;
  var still = root.classList.contains("still");
  var canObserve = "IntersectionObserver" in window;

  function syncHidden() { root.classList.toggle("is-hidden", document.hidden); }
  document.addEventListener("visibilitychange", syncHidden);
  syncHidden();

  function reveal() {
    if (still || !canObserve) return;
    var nodes = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
    var io = new IntersectionObserver(function (list) {
      list.forEach(function (e) {
        if (!e.isIntersecting) return;
        e.target.classList.add("in");
        io.unobserve(e.target);
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.12 });
    // Read every position first, then mark: what is already on screen stays as it is.
    var below = nodes.filter(function (n) { return n.getBoundingClientRect().top >= innerHeight; });
    below.forEach(function (n) {
      var kinds = (n.getAttribute("data-reveal") || "rise").split(/\s+/);
      if (kinds.indexOf("rise") >= 0) n.classList.add("rv");
      if (kinds.indexOf("line") >= 0) n.classList.add("ln");
      if (kinds.indexOf("draw") >= 0) n.classList.add("dr");
      var group = n.parentElement && n.parentElement.closest("[data-reveal-group]");
      if (group) {
        var sibs = Array.prototype.filter.call(n.parentElement.children, function (c) { return c.hasAttribute("data-reveal"); });
        n.classList.add("d-" + Math.min(sibs.indexOf(n), 5));
      }
      io.observe(n);
    });
  }

  function layers() {
    var box = document.querySelector("[data-layers]");
    if (!box || still || !canObserve) return;
    box.classList.add("pre");
    var io = new IntersectionObserver(function (list) {
      if (!list.some(function (e) { return e.isIntersecting; })) return;
      box.classList.remove("pre");
      box.classList.add("play");
      io.disconnect();
    }, { threshold: 0.35 });
    io.observe(box);
  }

  function swap(fn) {
    if (still || document.hidden || !document.startViewTransition) { fn(); return; }
    document.startViewTransition(fn);
  }

  reveal();
  layers();
  window.BacktideMotion = { swap: swap };
})();
