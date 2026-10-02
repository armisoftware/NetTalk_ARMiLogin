/*
  netwebauthn.js  -  client side of the NetWebAuthn extension templates
  Copy this file into your NetTalk web\scripts folder (same place as netweb.js).

  Server <-> client protocol (all POSTs go to the page that carries the extension,
  with a "_wa_" parameter, replies are small JSON objects {"ok":1,...} / {"ok":0,"err":"..."}):

    _wa_=lopts    -> {challenge,rpId}                      (login, step 1)
    _wa_=lverify  -> {next}                                (login, step 2)
    _wa_=ropts    -> {challenge,rpId,rpName,userId,userName,excl[]}   (enroll, step 1)
    _wa_=rverify  -> {}                                    (enroll, step 2)

  Requires a secure context (HTTPS or localhost) - the browser refuses WebAuthn otherwise.
*/
var netwebauthn = (function () {
  'use strict';

  var cfg = { url: '', next: '', texts: {}, debug: false };   // debug: true shows the browser error name even when the user cancels (use only while testing)

  function b64uToBuf(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    var bin = atob(s), buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { buf[i] = bin.charCodeAt(i); }
    return buf.buffer;
  }

  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  }

  function post(params) {
    var body = new URLSearchParams();
    for (var k in params) { if (Object.prototype.hasOwnProperty.call(params, k)) { body.append(k, params[k]); } }
    // _ajax_=1 tells NetTalk this is an AJAX call: it then answers with the bare reply and does not wrap it in the full page
    body.append('_ajax_', '1');
    var url = cfg.url + (cfg.url.indexOf('?') < 0 ? '?' : '&') + '_wa_=' + encodeURIComponent(params._wa_) + '&_ajax_=1';
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    }).then(function (r) { return r.text(); }).then(function (t) {
      var j;
      try { j = JSON.parse(t.slice(t.indexOf('{'), t.indexOf('}') + 1)); } catch (e) { throw new Error('bad reply'); }   // flat objects only; ignore anything after them
      if (!j.ok) { throw new Error(j.err || 'error'); }
      return j;
    });
  }

  // technical detail appended to the user message ONLY in debug mode, to help diagnosing (e.g. SecurityError: invalid domain)
  function errInfo(e) { return (cfg.debug && e) ? '  [' + (e.name || 'Error') + ': ' + (e.message || '') + ']' : ''; }   // only when cfg.debug is true

  function say(msg) { if (cfg.onMessage) { cfg.onMessage(msg); } else { window.alert(msg); } }

  function lsGet(k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } }
  function lsDel(k) { try { window.localStorage.removeItem(k); } catch (e) { /* private mode */ } }
  function lsSet(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }

  // ---- login --------------------------------------------------------------
  function doLogin() {
    if (!supported()) { say(cfg.texts.unsupported); return Promise.resolve(false); }
    return post({ _wa_: 'lopts' }).then(function (o) {
      return navigator.credentials.get({
        publicKey: {
          challenge: b64uToBuf(o.challenge),
          rpId: o.rpId,
          timeout: 60000,
          userVerification: 'required',
          allowCredentials: []            // discoverable credential: the device lists the passkeys of this site
        }
      });
    }).then(function (cred) {
      var r = cred.response;
      return post({
        _wa_: 'lverify',
        id: bufToB64u(cred.rawId),
        cdj: bufToB64u(r.clientDataJSON),
        ad: bufToB64u(r.authenticatorData),
        sig: bufToB64u(r.signature)
      });
    }).then(function (j) {
      lsSet('netwebauthn_known', '1');
      window.location.href = j.next || cfg.next;
      return true;
    }).catch(function (e) {
      if (e && e.message === 'unknown') {   // the device has a passkey the server no longer has: allow a new activation
        lsDel('netwebauthn_known');
        lsDel('netwebauthn_declined');
        say(cfg.texts.notRegistered || cfg.texts.loginFailed);
        return false;
      }
      if (e && e.name === 'NotAllowedError' && !cfg.debug) { return false; }   // user cancelled
      say(cfg.texts.loginFailed + errInfo(e));
      return false;
    });
  }

  // Device never activated: explain it instead of opening the OS passkey / QR window.
  // "Try anyway" is kept because a passkey synced from another device may exist.
  function login() {
    if (!supported()) { say(cfg.texts.unsupported); return Promise.resolve(false); }
    if (lsGet('netwebauthn_known') === '1' || !cfg.texts.notActive) { return doLogin(); }
    return new Promise(function (resolve) {
      modal(cfg.texts.notActive, [
        { label: cfg.texts.ok || 'OK', fn: function () { resolve(false); } },
        { label: cfg.texts.tryAnyway || 'Try anyway', link: true, fn: function () { resolve(doLogin()); } }
      ]);
    });
  }
  // ---- enrollment ---------------------------------------------------------
  function enroll() {
    if (!supported()) { say(cfg.texts.unsupported); return Promise.resolve(false); }
    var o;
    return post({ _wa_: 'ropts' }).then(function (opts) {
      o = opts;
      var excl = [];
      (o.excl || []).forEach(function (id) { excl.push({ type: 'public-key', id: b64uToBuf(id) }); });
      return navigator.credentials.create({
        publicKey: {
          challenge: b64uToBuf(o.challenge),
          rp: { id: o.rpId, name: o.rpName },
          user: { id: b64uToBuf(o.userId), name: o.userName, displayName: o.userName },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],     // ES256 only
          timeout: 60000,
          attestation: 'none',
          excludeCredentials: excl,
          authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' }
        }
      });
    }).then(function (cred) {
      var r = cred.response;
      if (!r.getPublicKey || !r.getAuthenticatorData) { throw new Error('browser too old'); }
      return post({
        _wa_: 'rverify',
        id: bufToB64u(cred.rawId),
        cdj: bufToB64u(r.clientDataJSON),
        ad: bufToB64u(r.getAuthenticatorData()),
        pk: bufToB64u(r.getPublicKey()),
        dev: (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || ''
      });
    }).then(function () {
      lsSet('netwebauthn_known', '1');
      return true;
    }).catch(function (e) {
      if (e && e.name === 'InvalidStateError') {   // this device already holds a passkey of this account: nothing to create
        lsSet('netwebauthn_known', '1');
        say(cfg.texts.alreadyActive || cfg.texts.enrollOk);
        return 'already';
      }
      if (e && e.name === 'NotAllowedError' && !cfg.debug) { return false; }
      say(cfg.texts.enrollFailed + errInfo(e));
      return false;
    });
  }

  // ---- offer (post-login page) -------------------------------------------
  function offer() {
    if (!supported()) { return; }
    if (lsGet('netwebauthn_known') === '1' || lsGet('netwebauthn_declined') === '1') { return; }
    if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(function (ok) {
        if (ok) { showOffer(); }
      });
    }
  }

  // Centered modal dialog with a dimmed backdrop. buttons: [{label, primary, link, keep, fn(close)}]
  // A button closes the dialog unless keep:true. Escape closes it.
  function modal(text, buttons) {
    var ov = document.createElement('div');
    ov.style.cssText = 'position:fixed;left:0;top:0;right:0;bottom:0;z-index:99998;background:rgba(0,0,0,.55);' +
      'display:flex;align-items:center;justify-content:center;padding:16px;box-sizing:border-box';
    var box = document.createElement('div');
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-modal', 'true');
    box.style.cssText = 'background:#fff;color:#222;width:100%;max-width:min(360px,100%);border-radius:10px;margin:auto;' +
      'box-shadow:0 8px 32px rgba(0,0,0,.45);padding:24px 20px 16px;font:16px/1.4 sans-serif;text-align:center;box-sizing:border-box';
    var msg = document.createElement('div');
    msg.style.cssText = 'margin-bottom:18px';
    msg.textContent = text;
    box.appendChild(msg);
    ov.appendChild(box);

    // On phones, position:fixed is relative to the layout viewport, which can be wider than the visible area
    // (page overflow / zoom). Fit the backdrop to the visual viewport so the box is really centered on screen.
    function fit() {
      var vv = window.visualViewport;
      if (!vv) { return; }
      ov.style.right = 'auto';
      ov.style.bottom = 'auto';
      ov.style.left = vv.offsetLeft + 'px';
      ov.style.top = vv.offsetTop + 'px';
      ov.style.width = vv.width + 'px';
      ov.style.height = vv.height + 'px';
    }

    function close() {
      document.removeEventListener('keydown', onKey, true);
      if (window.visualViewport) {
        window.visualViewport.removeEventListener('resize', fit);
        window.visualViewport.removeEventListener('scroll', fit);
      }
      if (ov.parentNode) { ov.parentNode.removeChild(ov); }
    }
    function onKey(ev) { if (ev.key === 'Escape') { close(); } }

    var first = null;
    buttons.forEach(function (b) {
      var el = document.createElement('button');
      el.type = 'button';
      el.textContent = b.label;
      el.style.cssText = b.link ?
        'display:block;width:100%;font-size:14px;padding:10px;background:none;border:0;text-decoration:underline;cursor:pointer' :
        'display:block;width:100%;font-size:16px;padding:12px;margin:0 0 8px;cursor:pointer';
      el.addEventListener('click', function () {
        if (!b.keep) { close(); }
        if (b.fn) { b.fn(close); }
      });
      box.appendChild(el);
      if (!first) { first = el; }
    });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(ov);
    fit();
    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', fit);
      window.visualViewport.addEventListener('scroll', fit);
    }
    if (first && first.focus) { first.focus(); }
    return close;
  }

  function showOffer() {
    var t = cfg.texts;
    modal(t.offerText, [
      { label: t.offerYes, keep: true, fn: function (close) {
          enroll().then(function (ok) { if (ok) { close(); if (ok !== 'already') { say(t.enrollOk); } } });
      } },
      { label: t.offerLater },
      { label: t.offerNever, link: true, fn: function () { lsSet('netwebauthn_declined', '1'); } }
    ]);
  }
  // Put the fingerprint button next to the form's save button (same look), or fall back to its own row.
  function placeButton(box, btn, setId) {
    var set = document.getElementById(setId);
    var save = set ? set.querySelector('button') : null;
    if (save) {
      btn.className = save.className.replace(/\s*nt-save-button\s*/g, ' ').replace(/\s*nt-button-with-icon\s*/g, ' ');
      btn.style.marginLeft = '8px';
      set.appendChild(btn);
      box.style.display = 'none';
    } else {
      box.style.display = 'block';
    }
  }
  return {
    init: function (c) { for (var k in c) { cfg[k] = c[k]; } return this; },
    supported: supported,
    login: login,
    enroll: enroll,
    offer: offer,
    placeButton: placeButton,
    known: function () { return lsGet('netwebauthn_known') === '1'; }
  };
})();
