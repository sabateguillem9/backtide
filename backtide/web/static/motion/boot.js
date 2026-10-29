/* backtide · motion switch. Load it in <head>, as a file (never inline), before the first
   paint, so the CSS knows from the start whether anything may move.
   .js      JavaScript runs.
   .still   reduced motion: everything visible and quiet from the start.
   .anim    play the entrance (motion.css). Never for a hidden tab, and taken away again when
            the page arrives through a view transition, whose cross-fade is its entrance.
   Nothing is hidden unless one of these classes says so. No storage, no network. */
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    root.classList.add("still");
    return;
  }
  if (!document.hidden) root.classList.add("anim");
  window.addEventListener("pagereveal", function (e) {
    if (e.viewTransition) root.classList.remove("anim");
  });
  // Once the entrance has played, whatever is rebuilt later (a language change) just appears.
  setTimeout(function () { root.classList.remove("anim"); }, 2600);
})();
