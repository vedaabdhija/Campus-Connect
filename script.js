/* CampusConnect — script.js */

// When served via Flask (http://), API is same origin. When file://, use explicit host.
const API = (location.protocol === 'file:') ? 'http://127.0.0.1:5000' : '';

// ── Token-aware fetch ─────────────────────────────────
function apiFetch(path, opts={}) {
  const tok = localStorage.getItem('token');
  opts.headers = Object.assign(
    {'Content-Type': 'application/json'},
    (tok && tok !== 'undefined' && tok !== 'null') ? {'X-Token': tok} : {},
    opts.headers || {}
  );
  return fetch(API + path, opts).catch(err => {
    console.warn('apiFetch error:', path, err.message);
    return new Response('{}', {status: 200, headers: {'Content-Type': 'application/json'}});
  });
}

// ── Login ─────────────────────────────────────────────
function login() {
  const u = document.getElementById('username')?.value.trim();
  const p = document.getElementById('password')?.value;
  const r = document.getElementById('role')?.value;
  if (!u || !p) { showToast('Enter username and password', 'error'); return; }
  const btn = document.querySelector('#loginBox .btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Logging in…'; }

  fetch(API + '/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: u, password: p, role: r})
  })
  .then(r => r.json())
  .then(d => {
    if (d.success) {
      localStorage.setItem('user',     d.user.username);
      localStorage.setItem('role',     d.user.role);
      localStorage.setItem('userData', JSON.stringify(d.user));
      if (d.token) localStorage.setItem('token', d.token);
      // Redirect to dashboard — works for both file:// and http://
      location.href = (location.protocol === 'file:') ? 'dashboard.html' : '/dashboard';
    } else {
      showToast(d.msg || 'Invalid credentials', 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Login'; }
    }
  })
  .catch(() => {
    showToast('Cannot reach server — make sure app.py is running', 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Login'; }
  });
}

function register() { showToast('Self-registration is disabled. Contact admin.', 'error'); }

function logout() {
  if (window._chatInterval) clearInterval(window._chatInterval);
  localStorage.clear();
  location.href = (location.protocol === 'file:') ? 'index.html' : '/';
}

function showRegister() {
  document.getElementById('loginBox').style.display = 'none';
  document.getElementById('registerBox').style.display = 'block';
}
function showLogin() {
  document.getElementById('registerBox').style.display = 'none';
  document.getElementById('loginBox').style.display = 'block';
}

// ── Toast ─────────────────────────────────────────────
let _toastTimer;
function showToast(msg, type='info') {
  let t = document.getElementById('gToast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'gToast';
    t.style.cssText = 'position:fixed;bottom:22px;right:22px;padding:11px 18px;border-radius:10px;' +
      'font-size:13px;font-weight:600;z-index:9999;transition:all .3s;' +
      'transform:translateY(70px);opacity:0;box-shadow:0 8px 24px rgba(0,0,0,.4);color:#fff;max-width:320px;';
    document.body.appendChild(t);
  }
  const cols = {info:'#4f8ef7', warning:'#f59e0b', error:'#ef4444', danger:'#ef4444', success:'#22c55e'};
  t.style.background = cols[type] || cols.info;
  t.textContent = msg;
  t.style.transform = 'translateY(0)'; t.style.opacity = '1';
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { t.style.transform = 'translateY(70px)'; t.style.opacity = '0'; }, 3500);
}

// ── QR Camera ─────────────────────────────────────────
let _qrScanner = null;
function startCameraScan() {
  const modal = document.getElementById('cameraModal');
  if (modal) modal.classList.add('open');
  if (typeof Html5Qrcode === 'undefined') { showToast('QR scanner not loaded', 'error'); return; }
  _qrScanner = new Html5Qrcode('reader');
  _qrScanner.start(
    {facingMode: 'environment'}, {fps: 10, qrbox: {width: 250, height: 250}},
    (text) => { stopCamera(); if (typeof submitCode === 'function') submitCode(text); },
    () => {}
  ).catch(err => { showToast('Camera error: ' + err, 'error'); stopCamera(); });
}
function stopCamera() {
  if (_qrScanner) { _qrScanner.stop().catch(() => {}).finally(() => { _qrScanner = null; }); }
  const modal = document.getElementById('cameraModal');
  if (modal) modal.classList.remove('open');
}

// Global unhandled promise rejection handler
window.addEventListener('unhandledrejection', function(e){
  console.error('Unhandled promise rejection:', e.reason);
});

// Enter key on login form
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.activeElement?.closest?.('#loginBox')) login();
});
