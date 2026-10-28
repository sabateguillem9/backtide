/* backtide · component behaviour. Load at the end of <body>. No dependencies, no storage,
   no markup from strings: elements are made with createElement and text with textContent.
   Position is set through the CSSOM (element.style), which a strict CSP allows; there is
   never a style attribute in the markup.

   - LanguageSwitch (.langs): one indicator slides to the pressed or current button.
   - Layers (.inside): pointing at a layer or its description lifts the one, lights the other. */
(function () {
  "use strict";

  function placeIndicators() {
    var groups = document.querySelectorAll(".langs");
    Array.prototype.forEach.call(groups, function (group) {
      var ind = group.querySelector(".langs__ind");
      if (!ind) {
        ind = document.createElement("span");
        ind.className = "langs__ind";
        ind.setAttribute("aria-hidden", "true");
        group.insertBefore(ind, group.firstChild);
        group.classList.add("has-ind");
      }
      var on = group.querySelector('[aria-pressed="true"], [aria-current="true"]');
      if (!on) return;
      ind.style.width = on.offsetWidth + "px";
      ind.style.transform = "translateX(" + on.offsetLeft + "px)";
    });
  }

  function layers() {
    var inside = document.querySelector(".inside");
    if (!inside) return;
    inside.addEventListener("pointerover", function (e) {
      var part = e.target.closest("[data-part]");
      if (part) inside.setAttribute("data-hl", part.getAttribute("data-part"));
      else inside.removeAttribute("data-hl");
    });
    inside.addEventListener("pointerleave", function () { inside.removeAttribute("data-hl"); });
  }

  placeIndicators();
  layers();
  // The indicator slides only after its first placement, and again once fonts settle widths.
  requestAnimationFrame(function () {
    Array.prototype.forEach.call(document.querySelectorAll(".langs"), function (g) { g.classList.add("ready"); });
  });
  if (document.fonts) document.fonts.ready.then(placeIndicators);
  window.addEventListener("resize", placeIndicators);
  window.BacktideComponents = { placeIndicators: placeIndicators };
})();
