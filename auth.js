'use strict';
// Talks to the server in server.js. Passwords are sent over HTTPS and hashed on the server.
// The login session is an httpOnly cookie, so this script never sees or stores the token.
const api = async (path, body) => {
  const r = await fetch('/api/' + path, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
  return { ok: r.ok, data: await r.json().catch(() => ({})) };
};
const form = document.getElementById('authForm');
if (form) {                                  // ---- login.html ----
  let mode = 'login';
  const set = m => {
    mode = m;
    tabLogin.setAttribute('aria-selected', m === 'login'); tabReg.setAttribute('aria-selected', m === 'register');
    nameRow.hidden = pwHint.hidden = m === 'login';
    password.autocomplete = m === 'login' ? 'current-password' : 'new-password';
    authGo.textContent = m === 'login' ? 'Log in' : 'Create account'; authErr.textContent = '';
  };
  tabLogin.onclick = () => set('login'); tabReg.onclick = () => set('register');
  form.onsubmit = async e => {
    e.preventDefault(); authErr.className = '';
    const body = { email: email.value.trim(), password: password.value };
    if (mode === 'register') body.name = name.value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(body.email)) return fail('Enter a valid email address.');
    if (body.password.length < 10) return fail('Password must be at least 10 characters.');
    authGo.disabled = true;
    const r = await api(mode, body); authGo.disabled = false;
    if (r.ok) location.href = 'index.html'; else fail(r.data.error || 'Something went wrong. Try again.');
  };
  const fail = m => { authErr.className = 'err'; authErr.textContent = m; };
} else {                                      // ---- index.html: show login / logout ----
  const link = document.getElementById('authLink');
  api('me').then(r => {
    if (r.ok) {
      link.textContent = 'Log out (' + r.data.name + ')';
      link.onclick = async () => { await api('logout', {}); location.reload(); };
    } else link.onclick = () => location.href = 'login.html';
  }).catch(() => { link.onclick = () => location.href = 'login.html'; });
}
