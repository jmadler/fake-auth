/* auth2 Admin — shared JS */

function getAdminKeyCookie() {
  const m = document.cookie.match(/auth2_admin_key=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

function adminAuth() {
  const key = getAdminKeyCookie();
  const h = {};
  if (key) h['Authorization'] = 'Bearer ' + key;
  return h;
}

function escapeHtml(s) {
  if (s == null) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
