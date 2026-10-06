/* @ds-bundle: {"format":4,"namespace":"Backtide","components":[{"name":"Wordmark"},{"name":"Mark"},{"name":"Tide"},{"name":"Message"},{"name":"Statement"},{"name":"DotButton"},{"name":"TextField"},{"name":"EmailCapture"},{"name":"LegalFooter"},{"name":"Document"}]} */
(function () {
  var React = window.React;
  var h = React.createElement;

  function cx() {
    return Array.prototype.filter.call(arguments, Boolean).join(" ");
  }

  // The wordmark, set in type. Always lowercase.
  function Wordmark(props) {
    var size = props.size || 64;
    return h("span", {
      className: cx("bt-wordmark", "bt-tone-" + (props.tone || "ink"), props.className),
      style: { fontSize: size + "px" },
      role: "img",
      "aria-label": "backtide",
    }, "backtide");
  }

  // The dot: the brand mark.
  function Mark(props) {
    var size = props.size || 16;
    return h("span", {
      className: cx("bt-mark", "bt-tone-" + (props.tone || "ink"), props.className),
      style: { width: size + "px", height: size + "px" },
      role: props.label ? "img" : undefined,
      "aria-label": props.label,
      "aria-hidden": props.label ? undefined : "true",
    });
  }

  // The tide: hops (|sin|) that grow into a wave (sin), drawn by a dot at its head.
  function smooth(t) { t = Math.min(1, Math.max(0, t)); return t * t * (3 - 2 * t); }
  function Tide(props) {
    var width = props.width || 480;
    var height = props.height || 120;
    var periods = props.periods || 2.25;
    var amplitude = props.amplitude == null ? 0.38 : props.amplitude;
    var hops = props.hops !== false;
    var vertical = props.orientation === "vertical";
    var showDot = props.dot !== false;
    var stroke = props.stroke || 2;
    var len = vertical ? height : width;
    var cross = vertical ? width : height;
    var pad = stroke * 5;
    var inner = len - pad * 2;
    var k = (2 * Math.PI * periods) / inner;
    var A = cross * amplitude;
    var base = cross / 2;
    var hopEnd = hops ? inner * 0.45 : 0;
    var points = [];
    for (var i = 0; i <= 160; i++) {
      var s = (inner * i) / 160;
      var sinv = Math.sin(k * s);
      var w = hops ? smooth((s - hopEnd * 0.6) / (hopEnd * 0.5)) : 1;
      var g = (1 - w) * 0.6 * Math.abs(sinv) + w * sinv;
      var along = pad + s;
      var off = base - A * g;
      points.push(vertical ? [off, along] : [along, off]);
    }
    if (vertical) points.reverse();
    var d = points.map(function (p, j) { return (j ? "L" : "M") + p[0].toFixed(1) + "," + p[1].toFixed(1); }).join("");
    var head = vertical ? points[points.length - 1] : points[points.length - 1];
    var gradId = "bt-tide-fade-" + (props.id || "x");
    var start = points[0];
    var solid = vertical ? [start[0], start[1] + inner * 0.5] : [start[0] + inner * 0.5, start[1]];
    return h("svg", {
      className: cx("bt-tide", "bt-tone-" + (props.tone || "ink"), props.className),
      width: width, height: height, viewBox: "0 0 " + width + " " + height,
      role: "img", "aria-label": props.label || "The tide",
    },
      hops ? h("defs", null, h("linearGradient", { id: gradId, gradientUnits: "userSpaceOnUse", x1: start[0], y1: start[1], x2: solid[0], y2: solid[1] },
        h("stop", { offset: "0", stopColor: "currentColor", stopOpacity: "0" }),
        h("stop", { offset: "1", stopColor: "currentColor", stopOpacity: "1" }))) : null,
      h("path", { d: d, fill: "none", stroke: hops ? "url(#" + gradId + ")" : "currentColor", strokeWidth: stroke, strokeLinecap: "round", strokeLinejoin: "round" }),
      showDot ? h("circle", { cx: head[0], cy: head[1], r: stroke * 4, fill: "currentColor" }) : null
    );
  }

  // A headline with the one line that explains it.
  function Message(props) {
    return h("div", { className: cx("bt-message", props.align === "start" && "bt-message-start", props.className) },
      h("h2", { className: "bt-message-title" }, props.title),
      props.children ? h("p", { className: "bt-message-text" }, props.children) : null);
  }

  // One sentence alone on screen.
  function Statement(props) {
    return h("p", { className: cx("bt-statement", props.className) }, props.children);
  }

  var arrow = h("svg", { viewBox: "0 0 16 16", width: 16, height: 16, fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": "true" },
    h("path", { d: "M3 8h10M9 4l4 4-4 4" }));

  // The dot as a button: the only call to action.
  function DotButton(props) {
    return h("button", {
      type: props.type || "button",
      className: cx("bt-dot-button", props.className),
      "aria-label": props.label,
      onClick: props.onClick,
      disabled: props.disabled,
    }, arrow);
  }

  // A field: a label, the text and one hairline. Never a box.
  function TextField(props) {
    return h("div", { className: cx("bt-text-field", props.className) },
      props.label ? h("label", { className: "bt-label", htmlFor: props.id }, props.label) : null,
      h("div", { className: "bt-field" },
        h("input", {
          id: props.id, name: props.name, type: props.type || "text",
          placeholder: props.placeholder, autoComplete: props.autoComplete,
          value: props.value, defaultValue: props.defaultValue, onChange: props.onChange,
          required: props.required, inputMode: props.inputMode,
        }),
        h("span", { className: "bt-line", "aria-hidden": "true" }),
        props.action || null));
  }

  // The waitlist: label, field, the dot as submit, one line on why and a privacy link.
  function EmailCapture(props) {
    var state = React.useState(null);
    var status = state[0], setStatus = state[1];
    var id = props.id || "bt-email";
    function submit(event) {
      event.preventDefault();
      var input = event.currentTarget.querySelector("input");
      if (!input.checkValidity()) { setStatus({ error: true, text: props.invalidText || "That doesn't look like an email." }); input.focus(); return; }
      if (props.onSubmit) props.onSubmit(input.value.trim(), setStatus);
    }
    return h("form", { className: cx("bt-capture", props.className), noValidate: true, onSubmit: submit },
      h("label", { className: "bt-label", htmlFor: id }, props.label || "Get early access"),
      h("div", { className: "bt-field" },
        h("input", { id: id, name: "email", type: "email", inputMode: "email", autoComplete: "email", required: true, placeholder: props.placeholder || "you@domain.com", onInput: function () { setStatus(null); } }),
        h("span", { className: "bt-line", "aria-hidden": "true" }),
        h(DotButton, { type: "submit", label: props.submitLabel || "Join the waitlist" })),
      h("p", { className: cx("bt-note", status && status.error && "bt-note-error"), "aria-live": "polite" },
        status ? status.text : [
          h("span", { key: "i" }, props.info || "One email when it's ready. Nothing else. Unsubscribe anytime."),
          " ",
          h("a", { key: "a", href: props.privacyHref || "privacy.html" }, props.privacyLabel || "Privacy policy"),
        ]));
  }

  // Footer of every public page: legal links and the language switch.
  function LegalFooter(props) {
    var links = props.links || [{ label: "Privacy policy", href: "privacy.html" }, { label: "Legal notice", href: "legal.html" }];
    var languages = props.languages || ["en", "es"];
    return h("footer", { className: cx("bt-footer", props.ruled && "bt-footer-ruled", props.className) },
      h("nav", { className: "bt-footer-links", "aria-label": "Legal" },
        links.map(function (link) { return h("a", { key: link.href, href: link.href }, link.label); })),
      h("div", { className: "bt-langs", role: "group", "aria-label": props.languageLabel || "Language" },
        languages.map(function (code) {
          return h("button", {
            key: code, type: "button", lang: code, "aria-pressed": String(code === (props.current || languages[0])),
            onClick: function () { if (props.onLanguage) props.onLanguage(code); },
          }, code.toUpperCase());
        })));
  }

  // A document page: the small wordmark home link, a title, the date, sections, the footer.
  function Document(props) {
    return h("div", { className: cx("bt-doc", props.className) },
      h("header", null, h("a", { className: "bt-doc-home", href: props.homeHref || "index.html" }, "backtide")),
      h("article", { className: "bt-doc-article" },
        h("h1", { className: "bt-doc-title" }, props.title),
        props.updated ? h("p", { className: "bt-doc-updated" }, props.updated) : null,
        (props.sections || []).map(function (section, i) {
          return h("section", { key: i, className: "bt-doc-section" },
            h("h2", null, section.heading),
            h("p", null, section.body));
        }),
        props.children),
      props.footer || null);
  }

  var api = { Wordmark: Wordmark, Mark: Mark, Tide: Tide, Message: Message, Statement: Statement, DotButton: DotButton, TextField: TextField, EmailCapture: EmailCapture, LegalFooter: LegalFooter, Document: Document };
  window.Backtide = Object.assign(window.Backtide || {}, api);
})();
