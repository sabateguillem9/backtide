// backtide · the lookout post. Our only script; HTMX (vendored in vendor/) does the fetching.
// No inline scripts and no inline styles in the pages (see the CSP): what moves is set here.
//
// Rules this file keeps:
// - It never turns text into HTML. Everything it writes is textContent (numbers and our own
//   words, read from data-* attributes that the server filled from backtide/web/i18n.py).
// - It moves only transform and opacity, and nothing at all with prefers-reduced-motion.
// - Nothing runs while the tab is hidden: timers stop, CSS animations pause (.is-hidden).
(function () {
  "use strict";

  var root = document.documentElement;
  var SVG = "http://www.w3.org/2000/svg";
  var reduce = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  var EASE_ARRIVE = "cubic-bezier(0.33, 1, 0.68, 1)";
  var EASE_TRAVEL = "cubic-bezier(0.37, 0, 0.63, 1)";
  var EASE_FALL = "cubic-bezier(0.32, 0, 0.67, 0)";

  function moving() {
    return !(reduce && reduce.matches) && typeof Element.prototype.animate === "function";
  }
  function inOut(t) {
    return 0.5 - Math.cos(Math.PI * t) / 2;
  }
  function out(t) {
    return 1 - Math.pow(1 - t, 3);
  }
  function clamp(v, lo, hi) {
    return Math.min(hi, Math.max(lo, v));
  }
  function when(text) {
    // "2026-10-16T15:54:26.442392Z" or "+00:00": every browser reads three decimals
    var ms = Date.parse(String(text || "").replace(/(\.\d{3})\d+/, "$1"));
    return isNaN(ms) ? null : ms;
  }

  // A page transition the browser skips (a fast second click) is not an error worth a console line.
  window.addEventListener("pagereveal", function (event) {
    var transition = event.viewTransition;
    if (!transition) return;
    ["ready", "finished", "updateCallbackDone"].forEach(function (name) {
      if (transition[name] && transition[name].catch) transition[name].catch(function () {});
    });
  });

  // -- a hidden tab rests ---------------------------------------------------------------------

  var wakers = [];
  function onVisibility() {
    root.classList.toggle("is-hidden", document.hidden);
    if (!document.hidden) wakers.forEach(function (wake) { wake(); });
  }
  document.addEventListener("visibilitychange", onVisibility);
  root.classList.toggle("is-hidden", document.hidden);

  // -- live relative times: <time data-ago datetime="..."> -------------------------------------

  var body = document.body;
  var AGE = {
    now: body.getAttribute("data-age-now") || "",
    sec: body.getAttribute("data-age-sec") || "",
    min: body.getAttribute("data-age-min") || "",
    hour: body.getAttribute("data-age-hour") || "",
    day: body.getAttribute("data-age-day") || "",
  };
  function ageText(ms) {
    var s = ms / 1000;
    if (s < -5) return null; // a clock ahead: leave what the server said
    if (s < 1) return AGE.now;
    if (s < 60) return AGE.sec.replace("{n}", String(Math.floor(s)));
    if (s < 3600) return AGE.min.replace("{n}", String(Math.floor(s / 60)));
    if (s < 48 * 3600) return AGE.hour.replace("{n}", String(Math.floor(s / 3600)));
    return AGE.day.replace("{n}", String(Math.floor(s / 86400)));
  }
  var ageTimer = 0;
  function tickAges() {
    window.clearTimeout(ageTimer);
    if (document.hidden) return;
    var next = 30000;
    document.querySelectorAll("time[data-ago][datetime]").forEach(function (el) {
      var at = when(el.getAttribute("datetime"));
      if (at === null) return;
      var ms = Date.now() - at;
      var text = ageText(ms);
      if (text && el.textContent !== text) el.textContent = text;
      if (ms < 60000) next = 1000;
      else if (ms < 3600000) next = Math.min(next, 15000);
    });
    ageTimer = window.setTimeout(tickAges, next);
  }
  wakers.push(tickAges);

  // -- numbers that count to their value -------------------------------------------------------

  var counted = {};
  function countTo(el, from, to, ms) {
    if (!moving() || from === to || document.hidden) {
      el.textContent = String(to);
      return;
    }
    var start = performance.now();
    function step(now) {
      var t = clamp((now - start) / ms, 0, 1);
      el.textContent = String(Math.round(from + (to - from) * out(t)));
      if (t < 1) window.requestAnimationFrame(step);
    }
    el.textContent = String(from);
    window.requestAnimationFrame(step);
  }
  function runCounters(scope, fromZero) {
    scope.querySelectorAll("[data-count]").forEach(function (el) {
      var name = el.getAttribute("data-count");
      var to = parseInt(el.textContent, 10);
      if (isNaN(to)) return;
      var from = name in counted ? counted[name] : fromZero ? 0 : to;
      counted[name] = to;
      countTo(el, from, to, 1100);
    });
  }

  // -- the tide ---------------------------------------------------------------------------------

  var frame = document.querySelector("[data-tide]");
  var tide = null; // its fixed geometry, read once
  var knownMarks = {};

  function readTide() {
    if (!frame) return null;
    var head = frame.querySelector(".tide-head");
    var view = frame.querySelector(".tide-now");
    if (!head || !view || !view.viewBox) return null;
    return {
      width: view.viewBox.baseVal.width,
      right: parseFloat(head.getAttribute("cx")),
      base: parseFloat(head.getAttribute("cy")),
      pos: frame.querySelector(".tide-pos"),
      hop: frame.querySelector(".tide-hop"),
    };
  }

  // Points of the drawn line, left to right: where the dot rides during the intro.
  function wavePoints() {
    var points = [];
    frame.querySelectorAll("svg.tide .tide-line").forEach(function (path) {
      if (typeof path.getTotalLength !== "function") return;
      var length = path.getTotalLength();
      var n = Math.max(2, Math.ceil(length / 2));
      for (var i = 0; i <= n; i++) {
        var p = path.getPointAtLength((length * i) / n);
        points.push([p.x, p.y]);
      }
    });
    points.sort(function (a, b) { return a[0] - b[0]; });
    return points;
  }
  function yAt(points, x) {
    if (!points.length) return tide.base;
    var lo = 0;
    var hi = points.length - 1;
    if (x <= points[lo][0]) return points[lo][1];
    if (x >= points[hi][0]) return points[hi][1];
    while (hi - lo > 1) {
      var mid = (lo + hi) >> 1;
      if (points[mid][0] <= x) lo = mid;
      else hi = mid;
    }
    var a = points[lo];
    var b = points[hi];
    var t = b[0] === a[0] ? 0 : (x - a[0]) / (b[0] - a[0]);
    return a[1] + (b[1] - a[1]) * t;
  }

  function rememberMarks(fresh) {
    frame.querySelectorAll(".tide-mark").forEach(function (mark) {
      var at = mark.getAttribute("data-at") || mark.getAttribute("cx");
      if (fresh && !knownMarks[at]) pulse(mark);
      knownMarks[at] = true;
    });
  }

  // A new snapshot: its mark arrives, and a ring leaves it once.
  function pulse(mark) {
    if (!moving()) return;
    mark.animate([{ transform: "scale(0)" }, { transform: "none" }], {
      duration: 500,
      easing: EASE_ARRIVE,
    });
    var ring = document.createElementNS(SVG, "circle");
    ring.setAttribute("class", "tide-ring");
    ring.setAttribute("cx", mark.getAttribute("cx"));
    ring.setAttribute("cy", mark.getAttribute("cy"));
    ring.setAttribute("r", mark.getAttribute("r"));
    mark.parentNode.insertBefore(ring, mark);
    var go = ring.animate(
      [
        { transform: "scale(1)", opacity: 0.9 },
        { transform: "scale(3.6)", opacity: 0 },
      ],
      { duration: 1500, easing: EASE_ARRIVE, delay: 250 }
    );
    go.onfinish = function () { ring.remove(); };
  }

  // The intro: the line draws in from the left (CSS) and the dot rides its head (here, in step).
  function intro() {
    if (!frame || !frame.classList.contains("is-intro")) return;
    var done = function () {
      frame.classList.remove("is-intro");
      frame.classList.add("can-rewind");
    };
    var win = lineParts().win;
    if (!moving() || !tide || !win || !win.getAnimations) {
      done();
      return;
    }
    var base = win.getAnimations()[0];
    if (!base) {
      done();
      return;
    }
    var points = wavePoints();
    var start = points.length ? points[0][0] : 0;
    var frames = [];
    for (var i = 0; i <= 48; i++) {
      var o = i / 48;
      var edge = inOut(o) * tide.width;
      var x = clamp(edge, start, tide.right);
      frames.push({
        offset: o,
        transform: "translate(" + (x - tide.right).toFixed(2) + "px," + (yAt(points, x) - tide.base).toFixed(2) + "px)",
        opacity: clamp((edge - start) / 30, 0, 1),
      });
    }
    var ride = tide.pos.animate(frames, { duration: 1800, easing: "linear", fill: "backwards" });
    base.ready.then(function () {
      if (base.startTime !== null) ride.startTime = base.startTime;
    });
    ride.onfinish = done;
    base.onfinish = done;
    base.oncancel = done;
  }

  // Something happened: the dot hops (its hops are the agent's activity) and the sea swells.
  var hopping = null;
  function stir() {
    if (!tide || !moving() || document.hidden || frame.classList.contains("is-intro")) return;
    if (!hopping && tide.hop) {
      hopping = tide.hop.animate(
        [
          { transform: "translateY(0)", easing: EASE_ARRIVE },
          { transform: "translateY(-7px)", offset: 0.42, easing: EASE_FALL },
          { transform: "translateY(0)" },
        ],
        { duration: 640 }
      );
      hopping.onfinish = function () { hopping = null; };
    }
    var swell = frame.querySelector(".tide-swell");
    if (swell && !(swell.getAnimations && swell.getAnimations().length)) {
      swell.animate(
        [{ transform: "scale(1, 1)" }, { transform: "scale(1, 1.6)" }, { transform: "scale(1, 1)" }],
        { duration: 1800, easing: EASE_TRAVEL }
      );
    }
  }

  // The heartbeat: calm while the agent works, still when it rests, quicker after a risk 3.
  var lastMove = 0;
  var alertUntil = 0;
  var heartTimer = 0;
  function heart() {
    window.clearTimeout(heartTimer);
    if (!frame || !document.getElementById("feed") || document.hidden) return;
    var now = Date.now();
    var watched = !!document.querySelector("#state .st-watched");
    var working = watched && now - lastMove < 30000;
    frame.classList.toggle("is-beating", working);
    frame.classList.toggle("is-alert", working && now < alertUntil);
    heartTimer = window.setTimeout(heart, 5000);
  }
  wakers.push(heart);

  // The rewind, drawn: the tide retracts to a snapshot and the dot goes back to rest on it.
  // A preview while you point at a row; held while a rewind is confirmed, runs and is done.
  // It returns false and changes nothing when the tide has no mark for ``iso``: a preview must
  // never show a rewind to a point that is not there. The line itself is redrawn by the stream
  // every minute, so its parts are looked up on every call and the retraction is put back on
  // the new line (reapply) after each redraw.
  var retracted = null;
  function lineParts() {
    return { win: frame && frame.querySelector(".tide-window"), inner: frame && frame.querySelector(".tide-inner") };
  }
  function retractTo(at) {
    var parts = lineParts();
    if (!tide || !parts.win || !parts.inner || typeof at !== "string") return false;
    var mark = null;
    frame.querySelectorAll(".tide-mark").forEach(function (m) {
      if (m.getAttribute("data-at") === at) mark = m;
    });
    if (!mark) return false;
    var x = parseFloat(mark.getAttribute("cx"));
    var y = parseFloat(mark.getAttribute("cy"));
    if (isNaN(x) || isNaN(y)) return false;
    var cut = ((tide.width - x) / tide.width) * 100;
    frame.classList.add("is-rewound");
    parts.win.style.transform = "translateX(" + (-cut).toFixed(3) + "%)";
    parts.inner.style.transform = "translateX(" + cut.toFixed(3) + "%)";
    tide.pos.style.transform = "translate(" + (x - tide.right).toFixed(2) + "px," + (y - tide.base).toFixed(2) + "px)";
    retracted = at;
    return true;
  }
  function restore() {
    retracted = null;
    if (!tide) return;
    var parts = lineParts();
    frame.classList.remove("is-rewound");
    if (parts.win) parts.win.style.transform = "";
    if (parts.inner) parts.inner.style.transform = "";
    tide.pos.style.transform = "";
  }
  function reapply() {
    if (retracted !== null && !retractTo(retracted)) restore();
  }
  window.backtide = Object.freeze({ retractTo: retractTo, restore: restore });

  // -- the conversation -------------------------------------------------------------------------

  var feed = document.getElementById("feed");
  var stick = true;
  var jump = document.querySelector(".ask .jump");

  function atBottom() {
    return window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 160;
  }
  function toBottom(smooth) {
    window.scrollTo({
      top: document.documentElement.scrollHeight,
      behavior: smooth && moving() ? "smooth" : "auto",
    });
  }
  function showJump(show) {
    if (jump) jump.hidden = !show;
  }
  window.addEventListener(
    "scroll",
    function () {
      stick = atBottom();
      if (stick) showJump(false);
    },
    { passive: true }
  );
  if (jump) {
    jump.addEventListener("click", function () {
      showJump(false);
      stick = true;
      toBottom(true);
    });
  }

  // The count of a folded line ("Ha borrado 120 archivos..."): the first number in the
  // sentence's own words. Names the agent chose are elements (.name), so they are never read.
  function countNode(line) {
    var said = line.querySelector(".said summary") || line.querySelector(".said");
    if (!said) return null;
    for (var node = said.firstChild; node; node = node.nextSibling) {
      if (node.nodeType !== 3) continue;
      var found = /\d+/.exec(node.data);
      if (!found) continue;
      var number = node.splitText(found.index);
      number.splitText(found[0].length);
      return number;
    }
    return null;
  }
  function countOf(line) {
    var said = line.querySelector(".said summary") || line.querySelector(".said");
    if (!said) return null;
    for (var node = said.firstChild; node; node = node.nextSibling) {
      if (node.nodeType !== 3) continue;
      var found = /\d+/.exec(node.data);
      if (found) return parseInt(found[0], 10);
    }
    return null;
  }

  function stagger(nodes, max) {
    var i = 0;
    nodes.forEach(function (node) {
      node.style.setProperty("--i", String(Math.min(i, max)));
      node.classList.add("is-new");
      i += 1;
    });
  }

  function onFeedChange(records) {
    var gone = {};
    var added = [];
    records.forEach(function (record) {
      record.removedNodes.forEach(function (node) {
        if (node.nodeType === 1 && node.id) {
          var burst = node.querySelector("details.burst");
          gone[node.id] = { count: countOf(node), open: !!(burst && burst.open) };
        }
      });
      record.addedNodes.forEach(function (node) {
        if (node.nodeType === 1 && node.classList.contains("line")) added.push(node);
      });
    });
    var agentMoved = false;
    var question = false;
    added.forEach(function (line) {
      var before = line.id ? gone[line.id] : undefined;
      if (before) {
        var burst = line.querySelector("details.burst");
        if (burst && before.open) burst.open = true;
        var to = countOf(line);
        if (to !== null && before.count !== null && to !== before.count) {
          var num = countNode(line);
          if (num) countTo(num, before.count, to, 700);
        }
        // HTMX lends a replaced element the old one's attributes until it settles (20 ms):
        // mark it once its own class is back.
        window.setTimeout(function () { line.classList.add("is-grown"); }, 60);
      } else {
        line.classList.add("is-new");
      }
      if (line.id) {
        agentMoved = true;
        if (line.querySelector(".dot-3")) alertUntil = Date.now() + 90000;
      }
      if (line.classList.contains("answer")) {
        question = true;
        var i = 0;
        line.querySelectorAll(".said > .para, .said .risky > li").forEach(function (part) {
          part.style.setProperty("--i", String(i));
          i += 1;
        });
      }
      if (line.classList.contains("you")) question = true;
    });
    if (agentMoved) {
      lastMove = Date.now();
      var ago = document.querySelector(".last-move time[data-ago]");
      var newest = feed.querySelector(".line:last-of-type time[datetime]");
      if (ago && newest) {
        ago.setAttribute("datetime", newest.getAttribute("datetime"));
        tickAges();
      }
      heart();
      stir();
    }
    if (question || (agentMoved && stick)) {
      toBottom(true);
    } else if (agentMoved && !atBottom()) {
      showJump(true);
    }
  }

  // -- history and snapshots: rows rise in ------------------------------------------------------

  function onRowsChange(records) {
    var rows = [];
    records.forEach(function (record) {
      record.addedNodes.forEach(function (node) {
        if (node.nodeType !== 1) return;
        if (node.classList.contains("event")) rows.push(node);
        else node.querySelectorAll(".event").forEach(function (e) { rows.push(e); });
      });
    });
    stagger(rows, 24);
  }

  var pinned = null; // the snapshot the rewind panel is about: the preview leaves it alone
  function snapshotRows() {
    var list = document.querySelector(".snaplist");
    if (!list) return;
    stagger(list.querySelectorAll(".snaprow"), 24);
    if (!tide) return;
    var hint = document.querySelector(".preview-hint");
    if (hint) hint.hidden = false;
    var current = null;
    function show(row) {
      if (pinned !== null || current === row) return;
      if (current) current.classList.remove("is-previewing");
      current = row;
      if (!row) {
        restore();
        return;
      }
      row.classList.add("is-previewing");
      if (!retractTo(row.getAttribute("data-rewind-to") || "")) restore();
    }
    list.querySelectorAll(".snaprow").forEach(function (row) {
      row.addEventListener("mouseenter", function () { show(row); });
      row.addEventListener("focusin", function () { show(row); });
      row.addEventListener("click", function () { show(current === row ? null : row); });
    });
    list.addEventListener("mouseleave", function () { show(null); });
    list.addEventListener("focusout", function (event) {
      if (!list.contains(event.relatedTarget)) show(null);
    });
  }

  // -- the rewind (T12b): confirm, run, done ----------------------------------------------------
  // The server sends each step (confirmation, result, or why not) into #rewind-panel. Here we
  // only hold the tide where the step says, move the focus to its title, and clear the panel on
  // "Cancel". Nothing is written as HTML: the panel is emptied node by node.

  var panel = document.getElementById("rewind-panel");
  function clearPanel() {
    while (panel.firstChild) panel.removeChild(panel.firstChild);
  }
  function onPanel() {
    var step = panel.querySelector(".rewind-step");
    if (frame) frame.classList.remove("is-rewinding");
    document.querySelectorAll(".snaprow.is-previewing").forEach(function (row) {
      row.classList.remove("is-previewing");
    });
    if (!step) {
      pinned = null;
      restore();
      return;
    }
    var view = step.getAttribute("data-view");
    var outcome = step.getAttribute("data-outcome");
    var at = step.getAttribute("data-rewind-to") || "";
    var hold = view === "confirm" || (view === "result" && (outcome === "done" || outcome === "problem"));
    pinned = hold ? at : null;
    if (!hold || !retractTo(at)) restore();
    var title = step.querySelector("#rewind-title");
    if (title) title.focus({ preventScroll: true });
    step.scrollIntoView({ block: "nearest", behavior: moving() ? "smooth" : "auto" });
  }
  if (panel) {
    panel.addEventListener("click", function (event) {
      var cancel = event.target.closest && event.target.closest(".rewind-cancel");
      if (!cancel) return;
      event.preventDefault();
      clearPanel();
      onPanel();
    });
  }
  document.body.addEventListener("htmx:beforeRequest", function (event) {
    var form = event.target;
    if (form && form.classList && form.classList.contains("rewind-confirm") && frame) {
      frame.classList.add("is-rewinding");
      retractTo(form.getAttribute("data-rewind-to") || "");
    }
  });
  document.body.addEventListener("htmx:afterSwap", function (event) {
    if (panel && event.target === panel) onPanel();
  });
  // A refusal of the guard (not ours to show) or a lost connection: say so, let go of the tide.
  function failed(event) {
    var form = event.target;
    if (!form || !form.classList || !form.classList.contains("rewind-confirm")) return;
    if (frame) frame.classList.remove("is-rewinding");
    var note = form.querySelector(".rewind-working");
    if (note) {
      note.textContent = form.getAttribute("data-failed") || "";
      note.classList.add("is-failed");
    }
    pinned = null;
    restore();
  }
  document.body.addEventListener("htmx:responseError", failed);
  document.body.addEventListener("htmx:sendError", failed);

  // -- wiring -----------------------------------------------------------------------------------

  document.body.addEventListener("htmx:sseMessage", function (event) {
    var target = event.target;
    if (target && target.id === "tide") {
      rememberMarks(true);
      runCounters(frame, false);
      reapply();
    } else if (target && target.id === "state") {
      heart();
    }
  });
  // A line about to be replaced in place must not lend its "just arrived" class to the new one.
  document.body.addEventListener("htmx:oobBeforeSwap", function (event) {
    var old = event.detail && event.detail.target;
    if (old && old.classList) old.classList.remove("is-new", "is-grown");
  });
  document.body.addEventListener("htmx:sseOpen", function () {
    var conn = document.querySelector(".last-move .conn");
    if (conn) conn.textContent = "";
  });
  document.body.addEventListener("htmx:sseError", function () {
    var holder = document.querySelector(".last-move");
    var conn = holder && holder.querySelector(".conn");
    if (conn) conn.textContent = holder.getAttribute("data-off") || "";
    frame && frame.classList.remove("is-beating");
  });
  document.body.addEventListener("htmx:afterRequest", function (event) {
    var form = event.target;
    if (form && form.classList && form.classList.contains("ask") && event.detail.successful) {
      form.reset();
    }
  });

  tide = readTide();
  if (frame) {
    rememberMarks(false);
    runCounters(frame, true);
    intro();
  }
  if (feed) {
    var lines = feed.querySelectorAll(".line[id] time[datetime]");
    if (lines.length) lastMove = when(lines[lines.length - 1].getAttribute("datetime")) || 0;
    feed.querySelectorAll(".line[id] .dot-3").forEach(function (dot) {
      var stamp = dot.parentNode.querySelector("time[datetime]");
      var at = stamp ? when(stamp.getAttribute("datetime")) : null;
      if (at !== null) alertUntil = Math.max(alertUntil, at + 90000);
    });
    new MutationObserver(onFeedChange).observe(feed, { childList: true });
    toBottom(false);
    window.addEventListener("load", function () { toBottom(false); });
  }
  var results = document.getElementById("results");
  if (results) {
    stagger(results.querySelectorAll(".event"), 24);
    new MutationObserver(onRowsChange).observe(results, { childList: true, subtree: true });
  }
  snapshotRows();
  heart();
  tickAges();
})();
