// Registering a passkey (T26-3b-2): the service makes the challenge and checks the answer; this
// only carries them between the browser's navigator.credentials and our own page. No text from
// outside ever goes into the page as HTML: only textContent.
(function () {
  "use strict";
  var form = document.getElementById("passkey-form");
  if (!form) return;
  var status = document.getElementById("passkey-status");

  function say(text, failed) {
    status.textContent = text;
    status.classList.toggle("is-error", Boolean(failed));
    form.elements.name.toggleAttribute("aria-invalid", Boolean(failed));
  }
  function fromB64url(text) {
    var b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var raw = atob(b64), out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }
  function toB64url(buffer) {
    var bytes = new Uint8Array(buffer), raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function post(url, fields) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString()
    }).then(function (response) { return response.json(); });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!window.PublicKeyCredential || !navigator.credentials || location.hostname !== "backtide.localhost") {
      say(form.dataset.unsupported, true);
      return;
    }
    var name = form.elements.name.value.trim();
    var csrf = form.dataset.csrf;
    post(form.dataset.begin, { csrf: csrf }).then(function (begun) {
      if (!begun.ok) throw new Error(begun.message);
      var options = JSON.parse(begun.options);
      options.challenge = fromB64url(options.challenge);
      options.user.id = fromB64url(options.user.id);
      (options.excludeCredentials || []).forEach(function (c) { c.id = fromB64url(c.id); });
      return navigator.credentials.create({ publicKey: options });
    }).then(function (credential) {
      var answer = {
        id: credential.id,
        rawId: toB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toB64url(credential.response.clientDataJSON),
          attestationObject: toB64url(credential.response.attestationObject),
          transports: credential.response.getTransports ? credential.response.getTransports() : []
        }
      };
      return post(form.dataset.finish, { csrf: csrf, name: name, answer: JSON.stringify(answer) });
    }).then(function (finished) {
      if (!finished.ok) throw new Error(finished.message);
      say(form.dataset.done);
      window.setTimeout(function () { window.location.reload(); }, 800);
    }).catch(function (error) {
      // The browser's own words are in its language and point elsewhere: ours, when it was the
      // person (cancelled, or the time ran out). Anything else: the service's message.
      if (error && error.name === "NotAllowedError") {
        say(form.dataset.cancelled, true);
      } else {
        say(form.dataset.failed + " " + (error && error.message ? error.message : ""), true);
      }
    });
  });
})();
