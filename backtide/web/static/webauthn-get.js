// Signing in with a passkey and touching it again (T26-3c): the service makes the challenge and
// checks the signature; this only carries them between navigator.credentials and our own page.
// No text from outside ever goes into the page as HTML: only textContent.
(function () {
  "use strict";
  var button = document.getElementById("webauthn-go");
  if (!button) return;
  var status = document.getElementById("webauthn-status");

  function say(text) {
    status.textContent = text;
    status.classList.add("is-error");
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
    }).then(function (response) {
      // A refusal that is not ours to word (an expired session's page, the Guard's bare status) is
      // not JSON: it says "it did not work", never the parser's own sentence.
      return response.json().catch(function () { return { ok: false, message: "" }; });
    });
  }

  button.addEventListener("click", function () {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      say(button.dataset.unsupported);
      return;
    }
    var csrf = button.dataset.csrf ? { csrf: button.dataset.csrf } : {};
    button.disabled = true;
    post(button.dataset.begin, csrf).then(function (begun) {
      if (!begun.ok) throw new Error(begun.message);
      var options = JSON.parse(begun.options);
      options.challenge = fromB64url(options.challenge);
      (options.allowCredentials || []).forEach(function (c) { c.id = fromB64url(c.id); });
      return navigator.credentials.get({ publicKey: options });
    }).then(function (credential) {
      var answer = {
        id: credential.id,
        rawId: toB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toB64url(credential.response.clientDataJSON),
          authenticatorData: toB64url(credential.response.authenticatorData),
          signature: toB64url(credential.response.signature)
        }
      };
      return post(button.dataset.finish, Object.assign({ answer: JSON.stringify(answer) }, csrf));
    }).then(function (finished) {
      if (!finished.ok) throw new Error(finished.message);
      window.location.assign(finished.target || button.dataset.target);
    }).catch(function (error) {
      button.disabled = false;
      if (error && error.name === "NotAllowedError") {
        say(button.dataset.cancelled);
      } else {
        say(button.dataset.failed + " " + (error && error.message ? error.message : ""));
      }
    });
  });
})();
