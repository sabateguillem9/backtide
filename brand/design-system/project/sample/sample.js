/* backtide · the sample page's own behaviour. No storage: the theme switch lasts until
   you reload. Text only through textContent; classes and attributes, never markup. */
(function () {
  "use strict";
  var root = document.documentElement;
  var place = function () { if (window.BacktideComponents) window.BacktideComponents.placeIndicators(); };
  var swap = function (fn) { if (window.BacktideMotion) window.BacktideMotion.swap(fn); else fn(); };

  function press(group, button) {
    Array.prototype.forEach.call(group.querySelectorAll("button"), function (b) {
      b.setAttribute("aria-pressed", String(b === button));
    });
    place();
  }

  // The theme: light or dark, for this visit only.
  var themes = document.querySelector("[data-theme-switch]");
  if (themes) {
    themes.addEventListener("click", function (e) {
      var b = e.target.closest("[data-set-theme]");
      if (!b || b.getAttribute("aria-pressed") === "true") return;
      swap(function () {
        root.setAttribute("data-theme", b.getAttribute("data-set-theme"));
        press(themes, b);
      });
    });
  }

  // Language and chips: only their pressed state, to show the component.
  Array.prototype.forEach.call(document.querySelectorAll("[data-demo-langs], [data-chips]"), function (group) {
    group.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (b) press(group, b);
    });
  });

  // The switches say their state in words too.
  Array.prototype.forEach.call(document.querySelectorAll("[data-switch]"), function (input) {
    input.addEventListener("change", function () {
      var word = input.closest(".switch").querySelector("[data-switch-state]");
      if (word) word.textContent = input.checked ? "On" : "Off";
    });
  });

  // Replays: put .anim back on one part of the page for one more entrance.
  function replay(el) {
    if (!el || root.classList.contains("still")) return;
    root.classList.remove("anim");
    el.classList.remove("anim");
    void el.offsetWidth;
    el.classList.add("anim");
    setTimeout(function () { el.classList.remove("anim"); }, 2600);
  }
  var targets = {
    entrance: function () { return document.querySelector(".ds-hero"); },
    icons: function () {
      var sheet = document.querySelector("[data-icon-sheet]");
      if (sheet) sheet.classList.add("enter-list");
      return sheet;
    },
    draw: function () { return document.querySelector("[data-draw-demo]").parentElement; },
  };
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-replay]");
    if (b) replay(targets[b.getAttribute("data-replay")]());
  });

  // The curves: four dots cross the same track, each with its own easing.
  var ease = document.querySelector("[data-ease-demo]");
  var play = document.querySelector("[data-play-ease]");
  if (ease && play) play.addEventListener("click", function () { ease.classList.toggle("is-on"); });

  // A view transition inside the page.
  var vt = document.querySelector("[data-vt-demo]");
  var vtButton = document.querySelector("[data-vt-toggle]");
  if (vt && vtButton) {
    vtButton.addEventListener("click", function () {
      swap(function () {
        var open = vt.classList.toggle("is-open");
        vtButton.setAttribute("aria-pressed", String(open));
        vtButton.textContent = open ? "Close the card" : "Open the card";
      });
    });
  }

  // Contrast, measured again here from the computed colours of both themes.
  function rgb(s) {
    var m = s.match(/\d+(\.\d+)?/g);
    return m ? m.slice(0, 3).map(Number) : [0, 0, 0];
  }
  function lum(c) {
    var v = c.map(function (x) { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
    return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
  }
  function ratio(a, b) {
    var la = lum(a), lb = lum(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  }
  function measure() {
    var probe = document.createElement("span");
    document.body.appendChild(probe);
    var read = function (name) { probe.style.color = "var(--" + name + ")"; return rgb(getComputedStyle(probe).color); };
    var texts = ["ink", "ink-soft", "ink-muted", "clay", "info", "ok", "warn", "danger", "state-preview", "state-done",
      "agent-1", "agent-2", "agent-3", "agent-4", "agent-5", "agent-6", "risk-0", "risk-1", "risk-2", "risk-3",
      "state-working", "state-idle", "state-frozen", "state-waiting", "state-rewinding", "state-sensor-down"];
    var grounds = ["paper", "band", "hover", "hold-wash"];
    var before = root.getAttribute("data-theme");
    var results = [];
    ["light", "dark"].forEach(function (theme) {
      root.setAttribute("data-theme", theme);
      texts.forEach(function (t) {
        grounds.forEach(function (g) { results.push({ theme: theme, text: t, on: g, ratio: ratio(read(t), read(g)) }); });
      });
    });
    root.setAttribute("data-theme", before);
    probe.remove();
    return results;
  }
  var out = document.querySelector("[data-live-contrast]");
  if (out) {
    var all = measure();
    var low = all.reduce(function (a, b) { return a.ratio < b.ratio ? a : b; });
    var failing = all.filter(function (r) { return r.ratio < 4.5; }).length;
    out.textContent = all.length + " pairs, " + failing + " under 4.5:1; the lowest is " +
      low.text + " on " + low.on + " (" + low.theme + "), " + low.ratio.toFixed(2) + ":1";
    window.BacktideContrast = all;
  }
})();
