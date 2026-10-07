'use strict';
/* =====================================================================
   Admin dashboard. Vanilla JS + Supabase.
   This UI only hides screens for convenience. Real authorization is done
   by Row Level Security and SECURITY DEFINER functions in the database.
   ===================================================================== */
// CONFIG (Supabase URL, anon key, page size) is loaded from config.js
const db = supabase.createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY);

/* ---------- helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const view = $('#view'), dlg = $('#dlg');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const S = { me: null, settings: {}, cats: [], brands: [], channel: null };
const money = n => new Intl.NumberFormat(undefined, { style: 'currency', currency: S.settings.currency || 'NGN', maximumFractionDigits: 0 }).format(n || 0);
const date = d => new Date(d).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
const one = v => (Array.isArray(v) ? v[0] : v) || null;
const slugify = s => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const isSuper = () => S.me?.role === 'super_admin';
/* Convenience only: the database enforces every one of these permissions too. */
const can = p => isSuper() || (S.me?.permissions == null || S.me.permissions.includes(p));
const NAV = { dashboard: 'orders.view', deliveries: 'rider', orders: 'orders.view', products: 'products.manage', categories: 'products.manage',
  inventory: ['inventory.manage', 'products.manage'], customers: 'customers.view', reviews: 'reviews.moderate', staff: 'super', settings: null };
const allowed = n => { const r = NAV[n]; return r === null ? true : r === 'rider' ? (S.me?.role === 'store_admin' && (S.me.permissions || []).includes('rider.deliver')) : r === 'super' ? isSuper() : Array.isArray(r) ? r.some(can) : can(r); };
const STATUSES = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
const PAYMENTS = ['unpaid', 'paid', 'failed', 'refunded'];
const opts = (list, sel, blank) => (blank ? `<option value="">${blank}</option>` : '') + list.map(v => { const [val, label] = Array.isArray(v) ? v : [v, v[0].toUpperCase() + v.slice(1)]; return `<option value="${esc(val)}" ${String(sel) === String(val) ? 'selected' : ''}>${esc(label)}</option>`; }).join('');

function toast(msg, err) {
  const el = Object.assign(document.createElement('div'), { className: 'toast' + (err ? ' err' : ''), textContent: msg });
  $('#toasts').append(el); setTimeout(() => el.remove(), 3500);
}
const params = () => { const [path, qs] = (location.hash.slice(1) || '/dashboard').split('?'); return { path, p: Object.fromEntries(new URLSearchParams(qs || '')) }; };
const setParam = (k, v) => { const { path, p } = params(); v ? p[k] = v : delete p[k]; if (k !== 'page') delete p.page; location.hash = `#${path}?${new URLSearchParams(p)}`; };
const skeleton = () => '<div class="skel"></div>';
const empty = t => `<div class="state">${t}</div>`;
const table = (cols, rows) => rows.length ? `<div class="tablewrap" tabindex="0"><table><thead><tr>${cols.map(c => `<th>${c[0]}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${cols.map(c => `<td>${c[1](r)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : empty('Nothing to show yet.');
const pager = (page, total) => { const n = Math.ceil(total / CONFIG.PAGE_SIZE); return n > 1 ? `<div class="foot" style="justify-content:center;align-items:center"><button class="btn sm ghost" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>Previous</button>Page ${page} of ${n}<button class="btn sm ghost" data-page="${page + 1}" ${page >= n ? 'disabled' : ''}>Next</button></div>` : ''; };
const pill = (t, kind) => `<span class="pill ${kind || ''}">${esc(t)}</span>`;
const range = page => [(page - 1) * CONFIG.PAGE_SIZE, page * CONFIG.PAGE_SIZE - 1];
function openDlg(html) { dlg.innerHTML = `<div class="dlg">${html}</div>`; if (!dlg.open) dlg.showModal(); }
const closeDlg = () => dlg.open && dlg.close();
const fail = (sel, e) => { $(sel).innerHTML = `<div class="msg err">${esc(e.message || e)}</div>`; };

/* ---------- auth gate ---------- */
let mfaMode = false;                                  // true while the 6-digit code screen is showing
const LOGIN_HTML = $('#loginForm').innerHTML;         // remembered so the password form can be restored
function showLogin(msg) {
  if (mfaMode) { $('#loginForm').innerHTML = LOGIN_HTML; mfaMode = false; }
  $('#shell').hidden = true; $('#loginScreen').hidden = false;
  $('#loginMsg').innerHTML = msg ? `<div class="msg err">${esc(msg)}</div>` : '';
}
async function enter(user) {
  if (!user) return showLogin();
  // Password accepted but the account uses two-step verification: ask for the code before anything loads.
  const { data: aal } = await db.auth.mfa.getAuthenticatorAssuranceLevel();
  if (aal && aal.nextLevel === 'aal2' && aal.currentLevel !== 'aal2') return showMfaChallenge();
  const { data } = await db.from('profiles').select('full_name,role,status,permissions').eq('id', user.id).maybeSingle();
  if (!data || data.status !== 'active' || !['store_admin', 'super_admin'].includes(data.role)) {
    await db.auth.signOut(); return showLogin('This account does not have admin access.');
  }
  S.me = { id: user.id, ...data };
  const [s, c, b] = await Promise.all([
    db.from('store_settings').select('key,value'), db.from('categories').select('id,name').order('sort_order'), db.from('brands').select('id,name').order('name')]);
  S.settings = Object.fromEntries((s.data || []).map(r => [r.key, r.value]));
  S.cats = c.data || []; S.brands = b.data || [];
  $('#loginScreen').hidden = true; $('#shell').hidden = false;
  refreshMfaBanner();
  $('#brandName').textContent = S.settings.store_name || 'Admin';
  $('#meName').textContent = `${data.full_name || 'Admin'} (${data.role.replace('_', ' ')})`;
  if (!S.channel) S.channel = db.channel('admin-orders').on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'orders' }, p => {
    toast(`New order ${p.new.order_number}`); if (['/orders', '/dashboard'].includes(params().path)) route();
  }).subscribe();
  if (allowed('deliveries') && !S.riderChannel) S.riderChannel = db.channel('rider-orders').on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'orders', filter: `rider_id=eq.${user.id}` }, p => {
    if (p.new.status === 'shipped') toast(`Delivery assigned: ${p.new.order_number}`); if (params().path === '/deliveries') route();
  }).subscribe();
  route();
}
function showMfaChallenge() {
  $('#shell').hidden = true; $('#loginScreen').hidden = false; mfaMode = true;
  $('#loginForm').innerHTML = `<h1>Two-step verification</h1><div id="loginMsg"></div><p>Open your authenticator app and enter the 6-digit code.</p>
    <label for="mfaCode">Code</label><input id="mfaCode" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required>
    <button class="btn pri" style="width:100%;margin-top:14px">Verify</button><p style="margin-top:12px"><a href="#" id="mfaOut"><u>Use a different account</u></a></p>`;
  $('#mfaCode').focus();
  $('#mfaOut').onclick = async ev => { ev.preventDefault(); await db.auth.signOut({ scope: 'local' }); showLogin(); };
}
async function verifyMfaCode() {
  const code = $('#mfaCode').value.trim();
  const { data: f } = await db.auth.mfa.listFactors(); const factor = f?.totp?.[0];
  if (!factor) { mfaMode = false; return showLogin('No authenticator is set up for this account.'); }
  const ch = await db.auth.mfa.challenge({ factorId: factor.id });
  const v = ch.error ? ch : await db.auth.mfa.verify({ factorId: factor.id, challengeId: ch.data.id, code });
  if (v.error) { $('#loginMsg').innerHTML = '<div class="msg err">That code is not correct. Try again.</div>'; return; }
  const { data: { user } } = await db.auth.getUser();
  mfaMode = false; $('#loginForm').innerHTML = LOGIN_HTML; enter(user);
}

/* ---------- two-step verification set-up (any staff member) ---------- */
async function refreshMfaBanner() {
  const { data: f } = await db.auth.mfa.listFactors();
  S.mfaOn = (f?.totp || []).length > 0;
  $('#mfaBanner').hidden = !(isSuper() && !S.mfaOn);
}
async function openMfaDialog() {
  const { data: f } = await db.auth.mfa.listFactors();
  const on = (f?.totp || []).length > 0;
  if (on) {
    openDlg(`<h2>Two-step verification</h2><p>It is <b>on</b>. You need a code from your authenticator app each time you sign in.</p>
      <div class="foot"><button class="btn ghost" data-close>Close</button><button class="btn dng" id="mfaOff">Turn off</button></div>`);
    $('#mfaOff').onclick = async () => {
      if (!confirm('Turn off two-step verification? Your account will be protected by your password only.')) return;
      const { error } = await db.auth.mfa.unenroll({ factorId: f.totp[0].id });
      if (error) return toast(error.message, true);
      toast('Two-step verification is off'); closeDlg(); refreshMfaBanner();
    };
    return;
  }
  for (const x of (f?.all || []).filter(x => x.status === 'unverified')) await db.auth.mfa.unenroll({ factorId: x.id }); // clear abandoned attempts
  const { data: { user: acct } } = await db.auth.getUser();
  // The app shows "<store name> Admin" and the account email, instead of the website address.
  const { data, error } = await db.auth.mfa.enroll({ factorType: 'totp', issuer: `${S.settings.store_name || 'Store'} Admin`, friendlyName: acct?.email || 'Authenticator' });
  if (error) return toast(error.message, true);
  openDlg(`<h2>Set up two-step verification</h2>
    <ol style="padding-left:18px;margin-bottom:10px"><li>Install an authenticator app, such as Google Authenticator, Microsoft Authenticator or Authy.</li><li>Scan this code, or type the key by hand.</li><li>Enter the 6-digit code the app shows.</li></ol>
    <div style="text-align:center"><img id="mfaQr" alt="QR code to scan" width="180" height="180"></div>
    <p style="word-break:break-all;text-align:center"><small>Key: <b>${esc(data.totp.secret)}</b></small></p><div id="mfaMsg"></div>
    <form id="mfaForm" novalidate><label for="mfaCode2">6-digit code</label><input id="mfaCode2" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancel</button><button class="btn pri">Turn on</button></div></form>`);
  $('#mfaQr').src = data.totp.qr_code; // set as a property: the code contains quotes that would break the page if pasted into HTML
  $('#mfaForm').onsubmit = async ev => {
    ev.preventDefault();
    const ch = await db.auth.mfa.challenge({ factorId: data.id }); if (ch.error) return fail('#mfaMsg', ch.error);
    const v = await db.auth.mfa.verify({ factorId: data.id, challengeId: ch.data.id, code: $('#mfaCode2').value.trim() });
    if (v.error) return fail('#mfaMsg', 'That code is not correct. Try again.');
    toast('Two-step verification is on'); closeDlg(); refreshMfaBanner();
  };
}
$('#mfaBtn').addEventListener('click', openMfaDialog);
$('#mfaBannerBtn').addEventListener('click', openMfaDialog);

$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault(); if (mfaMode) return verifyMfaCode();
  const btn = $('#loginForm button'); btn.disabled = true;
  const { data, error } = await db.auth.signInWithPassword({ email: $('#lEmail').value.trim(), password: $('#lPass').value });
  btn.disabled = false;
  if (error) return showLogin(error.message);
  enter(data.user);
});
$('#logoutBtn').addEventListener('click', async () => { await db.auth.signOut({ scope: 'local' }); S.me = null; if (S.channel) { db.removeChannel(S.channel); S.channel = null; } showLogin(); });
$('#menuBtn').addEventListener('click', () => $('#side').classList.toggle('open'));
dlg.addEventListener('click', e => { if (e.target === dlg || e.target.dataset.close !== undefined) closeDlg(); });

/* ---------- router ---------- */
const routes = {};
let ctl = new AbortController();
const listen = (evt, fn) => view.addEventListener(evt, fn, { signal: ctl.signal }); // reset on every route change
async function route() {
  if (!S.me) return;
  const { path, p } = params(); let name = path.split('/')[1] || 'dashboard';
  document.querySelectorAll('#nav a').forEach(a => { a.hidden = !allowed(a.getAttribute('href').slice(2)); });
  if (!allowed(name)) { const first = Object.keys(NAV).find(allowed); if (first && first !== name) { location.hash = '#/' + first; return; } }
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#/' + name));
  $('#mobTitle').textContent = name[0].toUpperCase() + name.slice(1); $('#side').classList.remove('open');
  ctl.abort(); ctl = new AbortController();
  view.onclick = view.onchange = view.oninput = null;
  view.innerHTML = skeleton();
  try { await (routes[name] || routes.dashboard)(p); }
  catch (e) { console.error(e); view.innerHTML = `<div class="state"><p>${esc(e.message)}</p><button class="btn" id="retry">Try again</button></div>`; $('#retry').onclick = route; }
}
window.addEventListener('hashchange', route);
const head = (title, right = '') => `<div class="head"><h1>${title}</h1><div class="tools">${right}</div></div>`;
const bindPager = () => { listen('click', e => { const b = e.target.closest('[data-page]'); if (b) setParam('page', b.dataset.page); }); };

/* ---------- dashboard ---------- */
routes.dashboard = async () => {
  const since = new Date(Date.now() - 6 * 864e5); since.setHours(0, 0, 0, 0);
  const [st, orders, custs, paid] = await Promise.all([
    db.rpc('admin_dashboard_stats'),
    db.from('orders').select('order_number,total,status,created_at,ship_name').order('created_at', { ascending: false }).limit(6),
    db.from('admin_customer_stats').select('full_name,email,created_at').order('created_at', { ascending: false }).limit(6),
    db.from('orders').select('total,created_at').eq('payment_status', 'paid').neq('status', 'cancelled').gte('created_at', since.toISOString()),
  ]);
  if (st.error) throw st.error;
  const s = st.data, days = Array.from({ length: 7 }, (_, i) => { const d = new Date(since.getTime() + i * 864e5); return { key: d.toDateString(), label: d.toLocaleDateString([], { weekday: 'short' }), sum: 0 }; });
  (paid.data || []).forEach(o => { const d = days.find(x => x.key === new Date(o.created_at).toDateString()); if (d) d.sum += +o.total; });
  const max = Math.max(...days.map(d => d.sum), 1);
  const stat = (l, v, warn) => `<div class="stat ${warn ? 'warn' : ''}"><b>${v}</b><span>${l}</span></div>`;
  view.innerHTML = head('Dashboard') + `<div class="cards">${stat('Total sales (paid)', money(s.total_sales))}${stat('Total orders', s.total_orders)}${stat('Pending orders', s.pending_orders, s.pending_orders > 0)}${stat('Customers', s.total_customers)}${stat('Products', s.total_products)}${stat('Low-stock products', s.low_stock, s.low_stock > 0)}</div>
    <div class="panel"><h2>Sales, last 7 days</h2><div class="bars">${days.map(d => `<div class="bar" title="${money(d.sum)}"><i style="height:${Math.round(d.sum / max * 100)}%"></i>${d.label}</div>`).join('')}</div></div>
    <div class="panel"><h2>Recent orders</h2>${table([['Order', o => `<a href="#/orders?q=${esc(o.order_number)}"><u>${esc(o.order_number)}</u></a>`], ['Customer', o => esc(o.ship_name)], ['Total', o => money(o.total)], ['Status', o => pill(o.status)], ['Date', o => date(o.created_at)]], orders.data || [])}</div>
    <div class="panel"><h2>Recent customers</h2>${table([['Name', c => esc(c.full_name)], ['Email', c => esc(c.email)], ['Joined', c => date(c.created_at)]], custs.data || [])}</div>`;
};

/* ---------- orders ---------- */
routes.orders = async p => {
  const page = Math.max(1, +p.page || 1);
  let q = db.from('orders').select('*', { count: 'exact' }).order('created_at', { ascending: false });
  if (p.status) q = q.eq('status', p.status);
  if (p.pay) q = q.eq('payment_status', p.pay);
  if (p.q) { const t = p.q.replace(/[,()%*]/g, ' ').trim(); q = q.or(`order_number.ilike.%${t}%,ship_name.ilike.%${t}%,ship_email.ilike.%${t}%`); }
  const { data, count, error } = await q.range(...range(page));
  if (error) throw error;
  view.innerHTML = head('Orders', `<input id="sq" type="search" placeholder="Order no., name or email" value="${esc(p.q || '')}"><select id="fs" aria-label="Filter by order status">${opts(STATUSES, p.status, 'All statuses')}</select><select id="fp" aria-label="Filter by payment status">${opts(PAYMENTS, p.pay, 'All payments')}</select>`) +
    `<div class="panel">${table([['Order', o => `<b>${esc(o.order_number)}</b>`], ['Customer', o => esc(o.ship_name)], ['Total', o => money(o.total)], ['Status', o => pill(o.status, o.status === 'cancelled' ? 'bad' : o.status === 'delivered' ? 'ok' : 'warn')], ['Payment', o => pill((o.payment_method === 'cod' ? 'COD · ' : '') + o.payment_status, o.payment_status === 'paid' ? 'ok' : '')], ['Rider', o => o.rider_name ? esc(o.rider_name) : (o.status === 'shipped' ? pill('Needs rider', 'warn') : '')], ['Date', o => date(o.created_at)], ['', o => `<button class="btn sm" data-view="${o.id}">View</button>`]], data)}${pager(page, count)}</div>`;
  bindPager();
  $('#sq').onchange = e => setParam('q', e.target.value.trim());
  $('#fs').onchange = e => setParam('status', e.target.value); $('#fp').onchange = e => setParam('pay', e.target.value);
  listen('click', e => { const b = e.target.closest('[data-view]'); if (b) orderDetail(b.dataset.view); });
};
async function orderDetail(id) {
  const { data: o, error } = await db.from('orders').select('*, order_items(*), order_status_history(status,note,created_at), delivery_attempts(outcome,note,created_at)').eq('id', id).single();
  if (error) return toast(error.message, true);
  const dispatchable = can('orders.assign') && ['confirmed', 'processing', 'shipped'].includes(o.status) && (o.payment_method === 'cod' || o.payment_status === 'paid');
  const riders = dispatchable ? ((await db.rpc('list_riders')).data || []) : [];
  openDlg(`<h2>${esc(o.order_number)}</h2><div id="dMsg"></div>
    <div class="grid2"><div><b>Customer</b><br>${esc(o.ship_name)}<br>${esc(o.ship_email)}<br>${esc(o.ship_phone)}</div>
    <div><b>Delivery</b><br>${esc(o.ship_address)}<br>${esc(o.ship_city)}, ${esc(o.ship_state)}, ${esc(o.ship_country)}${o.delivery_notes ? `<br><i>${esc(o.delivery_notes)}</i>` : ''}</div></div>
    <div class="panel" style="margin-top:12px">${table([['Item', i => esc(i.product_name)], ['SKU', i => esc(i.product_sku)], ['Qty', i => i.quantity], ['Price', i => money(i.unit_price)], ['Line', i => money(i.unit_price * i.quantity)]], o.order_items)}
      <p style="text-align:right;margin-top:8px">Delivery ${money(o.shipping_fee)} · Tax ${money(o.tax_total)} · <b>Total ${money(o.total)}</b></p></div>
    <div class="grid2"><div><label for="oSt">Order status</label><select id="oSt">${opts(STATUSES.filter(st => st === o.status || (['pending', 'confirmed', 'cancelled'].includes(st) ? can('orders.accept') : st === 'processing' ? can('orders.pack') : can('orders.ship'))), o.status)}</select></div><div><label for="oPay">Payment status (${o.payment_method === 'cod' ? 'pay on delivery: set Paid once the cash is collected' : 'Paystack'})</label><select id="oPay" ${can('orders.payments') ? '' : 'disabled'}>${opts(PAYMENTS, o.payment_status)}</select></div></div>
    <ul class="hist" style="margin-top:12px">${[...o.order_status_history].sort((a, b) => a.created_at.localeCompare(b.created_at)).map(h => `<li>${date(h.created_at)}: ${esc(h.status)}</li>`).join('')}</ul>
    ${o.rider_name ? `<p style="margin-top:10px"><b>Rider:</b> ${esc(o.rider_name)} ${esc(o.rider_phone || '')}</p>` : ''}
    ${(o.delivery_attempts || []).filter(a => a.outcome === 'failed').map(a => `<div class="msg err">Failed delivery (${date(a.created_at)}): ${esc(a.note)}</div>`).join('')}
    ${o.status === 'shipped' && can('orders.assign') ? '<p style="margin-top:10px"><button class="btn sm ghost" type="button" id="oNewCode">Send the customer a new delivery code</button></p>' : ''}
    ${dispatchable ? `<div class="panel" style="margin-top:12px"><label for="oRider">${o.rider_name ? 'Reassign rider' : 'Assign rider and dispatch'}</label><div class="tools"><select id="oRider">${opts(riders.map(r => [r.id, r.full_name + (r.phone ? ' · ' + r.phone : '')]), o.rider_id, 'Choose a rider')}</select><button class="btn" type="button" id="oAssign">Assign</button></div>${riders.length ? '' : '<small>No riders yet. Add one under Staff with the Rider role.</small>'}</div>` : ''}
    <div class="foot"><button class="btn ghost" data-close>Close</button><button class="btn pri" id="oSave">Save changes</button></div>`);
  if ($('#oNewCode')) $('#oNewCode').onclick = async () => {
    if (!confirm('Create a new delivery code and email it to the customer? The old code stops working.')) return;
    const { error: err } = await db.rpc('regenerate_delivery_code', { p_order: id });
    err ? fail('#dMsg', err) : toast('New code sent to the customer');
  };
  if ($('#oAssign')) $('#oAssign').onclick = async () => {
    const rider = $('#oRider').value; if (!rider) return fail('#dMsg', 'Choose a rider first.');
    const { error: err } = await db.rpc('assign_rider', { p_order: id, p_rider: rider });
    if (err) return fail('#dMsg', err);
    toast('Rider assigned. Order is out for delivery.'); closeDlg(); route();
  };
  $('#oSave').onclick = async () => {
    const patch = { status: $('#oSt').value, payment_status: $('#oPay').value };
    if (patch.status === 'cancelled' && o.status !== 'cancelled' && !confirm('Cancel this order? Stock will be returned.')) return;
    if (o.status === 'cancelled' && patch.status !== 'cancelled') return fail('#dMsg', 'A cancelled order cannot be reopened; ask the customer to place a new order.');
    const { error: err } = await db.from('orders').update(patch).eq('id', id);
    if (err) return fail('#dMsg', err);
    toast('Order updated'); closeDlg(); route();
  };
}

/* ---------- products ---------- */
routes.products = async p => {
  const page = Math.max(1, +p.page || 1);
  let q = db.from('products').select('*, categories(name), brands(name), inventory(quantity), product_images(url,sort_order)', { count: 'exact' }).order('created_at', { ascending: false });
  if (p.q) { const t = p.q.replace(/[,()%*]/g, ' ').trim(); q = q.or(`name.ilike.%${t}%,sku.ilike.%${t}%`); }
  if (p.cat) q = q.eq('category_id', p.cat);
  const { data, count, error } = await q.range(...range(page));
  if (error) throw error;
  const thumb = r => `<img class="thumb" alt="" src="${esc([...(r.product_images || [])].sort((a, b) => a.sort_order - b.sort_order)[0]?.url || '')}">`;
  view.innerHTML = head('Products', `<input id="sq" type="search" placeholder="Name or SKU" value="${esc(p.q || '')}"><select id="fc" aria-label="Filter by category">${opts(S.cats.map(c => [c.id, c.name]), p.cat, 'All categories')}</select><button class="btn pri" data-edit="">Add product</button>`) +
    `<div class="panel">${table([['', thumb], ['Name', r => `<b>${esc(r.name)}</b><br><small>${esc(r.sku)}</small>`], ['Category', r => esc(r.categories?.name)], ['Price', r => money(r.discount_price ?? r.price) + (r.discount_price ? ` <s>${money(r.price)}</s>` : '')], ['Stock', r => one(r.inventory)?.quantity ?? 0], ['Status', r => r.is_active ? pill('Active', 'ok') : pill('Disabled', 'bad')],
      ['', r => `<div class="act"><button class="btn sm" data-edit="${r.id}">Edit</button><button class="btn sm ghost" data-toggle="${r.id}" data-on="${r.is_active}">${r.is_active ? 'Disable' : 'Enable'}</button><button class="btn sm dng" data-del="${r.id}">Delete</button></div>`]], data)}${pager(page, count)}</div>`;
  bindPager();
  $('#sq').onchange = e => setParam('q', e.target.value.trim()); $('#fc').onchange = e => setParam('cat', e.target.value);
  listen('click', async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.dataset.edit !== undefined) productForm(t.dataset.edit);
    if (t.dataset.toggle) { const { error: err } = await db.from('products').update({ is_active: t.dataset.on !== 'true' }).eq('id', t.dataset.toggle); err ? toast(err.message, true) : route(); }
    if (t.dataset.del && confirm('Delete this product permanently? Past orders keep their item details.')) {
      const { error: err } = await db.from('products').delete().eq('id', t.dataset.del); err ? toast(err.message, true) : (toast('Product deleted'), route());
    }
  });
};

async function productForm(id) {
  let p = { is_active: true }, inv = { quantity: 0, low_stock_threshold: +S.settings.low_stock_threshold || 5 }, imgs = [], specs = [];
  if (id) {
    const { data, error } = await db.from('products').select('*, inventory(quantity,low_stock_threshold), product_images(id,url,sort_order), product_specs(spec_key,spec_value,sort_order)').eq('id', id).single();
    if (error) return toast(error.message, true);
    p = data; inv = one(data.inventory) || inv; imgs = [...data.product_images].sort((a, b) => a.sort_order - b.sort_order); specs = [...data.product_specs].sort((a, b) => a.sort_order - b.sort_order);
  }
  const f = (n, l, v = '', t = 'text', x = '') => `<div><label for="f_${n}">${l}</label><input id="f_${n}" name="${n}" type="${t}" value="${esc(v)}" ${x}></div>`;
  const chk = (n, l) => `<label><input type="checkbox" name="${n}" ${p[n] ? 'checked' : ''}> ${l}</label>`;
  openDlg(`<h2>${id ? 'Edit product' : 'Add product'}</h2><div id="pMsg"></div><form id="pForm" novalidate>
    <div class="grid2">${f('name', 'Name *', p.name, 'text', 'required')}${f('sku', 'SKU *', p.sku, 'text', 'required')}</div>
    <div class="grid2"><div><label for="f_cat">Category *</label><select id="f_cat" name="category_id">${opts(S.cats.map(c => [c.id, c.name]), p.category_id, 'Select category')}</select></div>
      <div><label for="f_brand">Brand</label><input id="f_brand" name="brand" list="brandList" value="${esc(S.brands.find(b => b.id === p.brand_id)?.name || '')}"><datalist id="brandList">${S.brands.map(b => `<option value="${esc(b.name)}">`).join('')}</datalist></div></div>
    <label for="f_desc">Description</label><textarea id="f_desc" name="description" rows="3">${esc(p.description)}</textarea>
    <div class="grid3">${f('price', 'Price *', p.price, 'number', 'min="0" step="0.01" required')}${f('discount_price', 'Discount price', p.discount_price ?? '', 'number', 'min="0" step="0.01"')}${f('quantity', 'Stock quantity *', inv.quantity, 'number', 'min="0" step="1" required')}</div>
    ${f('low_stock_threshold', 'Low-stock threshold', inv.low_stock_threshold, 'number', 'min="0" step="1"')}
    <div class="flags">${chk('is_active', 'Active')}${chk('is_featured', 'Featured')}${chk('is_best_seller', 'Best seller')}${chk('is_new_arrival', 'New arrival')}</div>
    <label for="f_specs">Specifications (one per line, "Name: Value")</label><textarea id="f_specs" name="specs" rows="4">${esc(specs.map(s => `${s.spec_key}: ${s.spec_value}`).join('\n'))}</textarea>
    <label for="f_files">Images</label><div class="imgs" id="imgList">${imgs.map(i => `<div data-img="${i.id}" data-url="${esc(i.url)}"><img src="${esc(i.url)}" alt=""><button type="button" aria-label="Remove image">×</button></div>`).join('')}</div>
    <input type="file" id="f_files" accept="image/*" multiple>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancel</button><button class="btn pri" id="pSave">Save product</button></div></form>`);
  $('#imgList').onclick = async e => {
    const b = e.target.closest('button'), box = b?.parentElement; if (!b) return;
    if (!confirm('Remove this image?')) return;
    const { error } = await db.from('product_images').delete().eq('id', box.dataset.img); if (error) return toast(error.message, true);
    const path = box.dataset.url.split('/product-images/')[1]; if (path) db.storage.from('product-images').remove([decodeURIComponent(path)]);
    box.remove();
  };
  $('#pForm').onsubmit = ev => { ev.preventDefault(); saveProduct(id, imgs.length); };
}

async function saveProduct(id, existingImgs) {
  const form = $('#pForm'), fd = new FormData(form), btn = $('#pSave');
  const v = Object.fromEntries(fd), num = k => (v[k] === '' ? null : Number(v[k])), files = [...$('#f_files').files];
  const has = k => form.elements[k].checked;
  if (!v.name.trim() || !v.sku.trim() || !v.category_id) return fail('#pMsg', 'Name, SKU and category are required.');
  if (!(num('price') >= 0) || v.price === '') return fail('#pMsg', 'Enter a valid price.');
  if (num('discount_price') !== null && !(num('discount_price') >= 0 && num('discount_price') < num('price'))) return fail('#pMsg', 'Discount price must be lower than the price.');
  if (!Number.isInteger(num('quantity')) || num('quantity') < 0) return fail('#pMsg', 'Stock must be a whole number, 0 or more.');
  if (files.some(f => !f.type.startsWith('image/') || f.size > 5 * 1024 * 1024)) return fail('#pMsg', 'Images must be image files under 5 MB.');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    let brand_id = null; const bn = v.brand.trim();
    if (bn) {
      brand_id = S.brands.find(b => b.name.toLowerCase() === bn.toLowerCase())?.id;
      if (!brand_id) { const { data, error } = await db.from('brands').insert({ name: bn, slug: slugify(bn) }).select('id,name').single(); if (error) throw error; S.brands.push(data); brand_id = data.id; }
    }
    const row = { name: v.name.trim(), sku: v.sku.trim(), category_id: v.category_id, brand_id, description: v.description.trim(), price: num('price'), discount_price: num('discount_price'),
      is_active: has('is_active'), is_featured: has('is_featured'), is_best_seller: has('is_best_seller'), is_new_arrival: has('is_new_arrival') };
    let pid = id;
    if (id) { const { error } = await db.from('products').update(row).eq('id', id); if (error) throw error; }
    else { const { data, error } = await db.from('products').insert({ ...row, slug: slugify(`${row.name} ${row.sku}`) }).select('id').single(); if (error) throw error; pid = data.id; }
    let r = await db.from('inventory').upsert({ product_id: pid, quantity: num('quantity'), low_stock_threshold: num('low_stock_threshold') ?? 5 }); if (r.error) throw r.error;
    r = await db.from('product_specs').delete().eq('product_id', pid); if (r.error) throw r.error;
    const specRows = v.specs.split('\n').map(l => l.split(/:(.*)/s)).filter(a => a[0]?.trim() && a[1]?.trim()).map((a, i) => ({ product_id: pid, spec_key: a[0].trim(), spec_value: a[1].trim(), sort_order: i }));
    if (specRows.length) { r = await db.from('product_specs').insert(specRows); if (r.error) throw r.error; }
    for (const [i, file] of files.entries()) {
      const path = `${pid}/${Date.now()}-${i}-${file.name.replace(/[^\w.-]/g, '_')}`;
      const up = await db.storage.from('product-images').upload(path, file); if (up.error) throw up.error;
      const url = db.storage.from('product-images').getPublicUrl(path).data.publicUrl;
      r = await db.from('product_images').insert({ product_id: pid, url, sort_order: existingImgs + i }); if (r.error) throw r.error;
    }
    toast('Product saved'); closeDlg(); route();
  } catch (e) {
    fail('#pMsg', /duplicate key/.test(e.message) ? 'That SKU or product name already exists.' : e); btn.disabled = false; btn.textContent = 'Save product';
  }
}

/* ---------- categories ---------- */
routes.categories = async () => {
  const { data, error } = await db.from('categories').select('*, products(count)').order('sort_order');
  if (error) throw error; S.cats = data;
  view.innerHTML = head('Categories', '<button class="btn pri" data-cat="">Add category</button>') + `<div class="panel">${table([['', c => c.image_url ? `<img class="thumb" alt="" src="${esc(c.image_url)}">` : ''], ['Name', c => `<b>${esc(c.name)}</b>`], ['Products', c => c.products?.[0]?.count ?? 0], ['Order', c => c.sort_order], ['Visibility', c => c.is_active ? pill('Visible', 'ok') : pill('Hidden', 'bad')],
    ['', c => `<div class="act"><button class="btn sm" data-cat="${c.id}">Edit</button><button class="btn sm dng" data-del="${c.id}" data-n="${c.products?.[0]?.count ?? 0}">Delete</button></div>`]], data)}</div>`;
  view.onclick = async e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.cat !== undefined) return categoryForm(data.find(c => c.id === b.dataset.cat));
    if (b.dataset.del) {
      if (+b.dataset.n > 0) return toast('Move or delete this category’s products first, or hide it instead.', true);
      if (!confirm('Delete this category?')) return;
      const { error: err } = await db.from('categories').delete().eq('id', b.dataset.del); err ? toast(err.message, true) : (toast('Category deleted'), route());
    }
  };
};
function categoryForm(c = { is_active: true, sort_order: 0 }) {
  openDlg(`<h2>${c.id ? 'Edit category' : 'Add category'}</h2><div id="cMsg"></div><form id="cForm" novalidate>
    <label for="c_name">Name *</label><input id="c_name" value="${esc(c.name)}" required>
    <div class="grid2"><div><label for="c_ord">Sort order</label><input id="c_ord" type="number" value="${c.sort_order}"></div><div><label for="c_img">Image</label><input id="c_img" type="file" accept="image/*"></div></div>
    <div class="flags"><label><input type="checkbox" id="c_act" ${c.is_active ? 'checked' : ''}> Visible in store</label></div>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancel</button><button class="btn pri">Save category</button></div></form>`);
  $('#cForm').onsubmit = async e => {
    e.preventDefault(); const name = $('#c_name').value.trim(); if (!name) return fail('#cMsg', 'Name is required.');
    const row = { name, slug: slugify(name), sort_order: +$('#c_ord').value || 0, is_active: $('#c_act').checked }, file = $('#c_img').files[0];
    try {
      if (file) {
        if (!file.type.startsWith('image/') || file.size > 5 * 1024 * 1024) throw new Error('Image must be under 5 MB.');
        const path = `${Date.now()}-${file.name.replace(/[^\w.-]/g, '_')}`, up = await db.storage.from('category-images').upload(path, file); if (up.error) throw up.error;
        row.image_url = db.storage.from('category-images').getPublicUrl(path).data.publicUrl;
      }
      const { error } = c.id ? await db.from('categories').update(row).eq('id', c.id) : await db.from('categories').insert(row);
      if (error) throw error; toast('Category saved'); closeDlg(); route();
    } catch (err) { fail('#cMsg', /duplicate key/.test(err.message) ? 'A category with that name already exists.' : err); }
  };
}

/* ---------- inventory ---------- */
routes.inventory = async p => {
  const page = Math.max(1, +p.page || 1);
  const { data, count, error } = await db.from('inventory').select('product_id,quantity,low_stock_threshold,updated_at, products!inner(name,sku,is_active)', { count: 'exact' }).order('quantity').range(...range(page));
  if (error) throw error;
  const stat = r => r.quantity <= 0 ? pill('Out of stock', 'bad') : r.quantity <= r.low_stock_threshold ? pill('Low stock', 'warn') : pill('In stock', 'ok');
  view.innerHTML = head('Inventory') + `<div class="panel">${table([['Product', r => `<b>${esc(r.products.name)}</b>`], ['SKU', r => esc(r.products.sku)], ['Stock', r => `<input type="number" min="0" step="1" style="width:90px" data-f="quantity" data-id="${r.product_id}" value="${r.quantity}" aria-label="Stock for ${esc(r.products.name)}">`], ['Threshold', r => `<input type="number" min="0" step="1" style="width:90px" data-f="low_stock_threshold" data-id="${r.product_id}" value="${r.low_stock_threshold}" aria-label="Low-stock level for ${esc(r.products.name)}">`], ['Status', stat], ['Updated', r => date(r.updated_at)]], data)}${pager(page, count)}</div>`;
  bindPager();
  listen('change', async e => {
    const i = e.target.closest('[data-f]'); if (!i) return;
    const val = Number(i.value); if (!Number.isInteger(val) || val < 0) { toast('Enter a whole number, 0 or more.', true); return route(); }
    const { error: err } = await db.from('inventory').update({ [i.dataset.f]: val }).eq('product_id', i.dataset.id);
    err ? toast(err.message, true) : (toast('Inventory updated'), route());
  });
};

/* ---------- customers ---------- */
routes.customers = async p => {
  const page = Math.max(1, +p.page || 1);
  let q = db.from('admin_customer_stats').select('*', { count: 'exact' }).order('created_at', { ascending: false });
  if (p.q) { const t = p.q.replace(/[,()%*]/g, ' ').trim(); q = q.or(`full_name.ilike.%${t}%,email.ilike.%${t}%`); }
  const { data, count, error } = await q.range(...range(page));
  if (error) throw error;
  view.innerHTML = head('Customers', `<input id="sq" type="search" placeholder="Name or email" value="${esc(p.q || '')}">`) + `<div class="panel">${table([['Name', c => `<b>${esc(c.full_name)}</b>`], ['Email', c => esc(c.email)], ['Phone', c => esc(c.phone)], ['Joined', c => date(c.created_at)], ['Orders', c => c.order_count], ['Spent', c => money(c.total_spent)], ['Account', c => c.status === 'active' ? pill('Active', 'ok') : pill('Suspended', 'bad')],
    ['', c => (can('customers.manage') ? `<button class="btn sm ghost" data-id="${c.id}" data-s="${c.status}">${c.status === 'active' ? 'Suspend' : 'Reactivate'}</button>` : '') + (isSuper() ? ` <button class="btn sm ghost" data-mfa="${c.id}">Reset 2-step</button>` : '')]], data)}${pager(page, count)}</div>`;
  bindPager(); $('#sq').onchange = e => setParam('q', e.target.value.trim());
  listen('click', async e => {
    const mfa = e.target.closest('[data-mfa]');
    if (mfa) {
      if (!confirm('Reset two-step verification for this customer? Only do this after you have confirmed it is really them.')) return;
      const { error: err } = await db.rpc('admin_reset_mfa', { p_user: mfa.dataset.mfa });
      return err ? toast(err.message, true) : toast('Reset. The customer can now sign in with their password.');
    }
    const b = e.target.closest('[data-s]'); if (!b) return;
    const next = b.dataset.s === 'active' ? 'suspended' : 'active';
    if (next === 'suspended' && !confirm('Suspend this customer? They will not be able to place orders.')) return;
    const { error: err } = await db.from('profiles').update({ status: next }).eq('id', b.dataset.id); err ? toast(err.message, true) : route();
  });
};

/* ---------- reviews ---------- */
routes.reviews = async p => {
  const page = Math.max(1, +p.page || 1);
  const { data, count, error } = await db.from('reviews').select('*, products(name)', { count: 'exact' }).order('created_at', { ascending: false }).range(...range(page));
  if (error) throw error;
  view.innerHTML = head('Reviews') + `<div class="panel">${table([['Product', r => esc(r.products?.name)], ['Rating', r => '★'.repeat(r.rating) + '☆'.repeat(5 - r.rating)], ['Comment', r => `<div class="wrap">${esc(r.comment)}</div>`], ['Date', r => date(r.created_at)], ['Status', r => r.status === 'approved' ? pill('Visible', 'ok') : pill('Hidden', 'bad')],
    ['', r => `<div class="act"><button class="btn sm ghost" data-id="${r.id}" data-s="${r.status}">${r.status === 'approved' ? 'Hide' : 'Approve'}</button><button class="btn sm dng" data-del="${r.id}">Delete</button></div>`]], data)}${pager(page, count)}</div>`;
  bindPager();
  listen('click', async e => {
    const b = e.target.closest('button'); if (!b || b.dataset.page) return; let r;
    if (b.dataset.s) r = await db.from('reviews').update({ status: b.dataset.s === 'approved' ? 'hidden' : 'approved' }).eq('id', b.dataset.id);
    else if (b.dataset.del && confirm('Delete this review permanently?')) r = await db.from('reviews').delete().eq('id', b.dataset.del);
    if (r) r.error ? toast(r.error.message, true) : route();
  });
};

/* ---------- settings (super admin edits; store admins read only) ---------- */
routes.settings = async () => {
  const { data, error } = await db.from('store_settings').select('key,value'); if (error) throw error;
  const cur = Object.fromEntries(data.map(r => [r.key, r.value])), ro = isSuper() ? '' : 'disabled';
  const fields = [['store_name', 'Store name'], ['store_email', 'Store email', 'email'], ['store_phone', 'Store phone'], ['store_address', 'Store address'], ['currency', 'Currency code (e.g. NGN, USD)'], ['shipping_flat_fee', 'Flat shipping fee', 'number'], ['free_shipping_threshold', 'Free shipping over (0 = never)', 'number'], ['tax_rate_percent', 'Tax rate %', 'number'], ['low_stock_threshold', 'Default low-stock threshold', 'number'], ['cod_max_amount', 'Pay-on-delivery limit per order (0 = no limit)', 'number']];
  view.innerHTML = head('Settings') + `<form class="panel" id="sForm" style="max-width:640px" novalidate>${isSuper() ? '' : '<div class="msg err">Only a super admin can change settings.</div>'}<div id="sMsg"></div>
    ${fields.map(([k, l, t = 'text']) => `<label for="s_${k}">${l}</label><input id="s_${k}" name="${k}" type="${t}" ${t === 'number' ? 'min="0" step="any"' : ''} value="${esc(cur[k])}" ${ro}>`).join('')}
    <label for="s_store_status">Store status</label><select id="s_store_status" name="store_status" ${ro}>${opts(['open', 'closed'], cur.store_status)}</select>
    <label for="s_cod_enabled">Pay on delivery</label><select id="s_cod_enabled" name="cod_enabled" ${ro}>${opts([['true', 'Enabled'], ['false', 'Disabled']], String(cur.cod_enabled ?? true))}</select>
    <div class="foot">${isSuper() ? '<button class="btn pri">Save settings</button>' : ''}</div></form>`;
  $('#sForm').onsubmit = async e => {
    e.preventDefault(); const v = Object.fromEntries(new FormData(e.target));
    if (!/^[A-Za-z]{3}$/.test(v.currency)) return fail('#sMsg', 'Currency must be a 3-letter code.');
    const rows = Object.entries(v).map(([key, val]) => ({ key, value: fields.find(f => f[0] === key)?.[2] === 'number' ? Number(val) || 0 : key === 'currency' ? val.toUpperCase() : key === 'cod_enabled' ? val === 'true' : val, is_public: key !== 'low_stock_threshold' }));
    const { error: err } = await db.from('store_settings').upsert(rows); if (err) return fail('#sMsg', err);
    rows.forEach(r => { S.settings[r.key] = r.value; }); $('#brandName').textContent = S.settings.store_name; toast('Settings saved');
  };
};

/* ---------- rider: my deliveries ---------- */
routes.deliveries = async () => {
  const { data, error } = await db.from('orders').select('*, order_items(product_name,quantity)').eq('rider_id', S.me.id).order('assigned_at', { ascending: false }).limit(40);
  if (error) throw error;
  const todo = data.filter(o => o.status === 'shipped'), done = data.filter(o => o.status !== 'shipped').slice(0, 10);
  const collect = o => o.payment_method === 'cod' && o.payment_status !== 'paid';
  view.innerHTML = head('My deliveries') + (todo.length ? todo.map(o => `<div class="panel">
      <h2>${esc(o.order_number)} ${collect(o) ? pill('Collect ' + money(o.total), 'warn') : pill('Already paid', 'ok')}</h2>
      <p><b>${esc(o.ship_name)}</b> · <a href="tel:${esc(o.ship_phone)}"><u>${esc(o.ship_phone)}</u></a></p>
      <p>${esc(o.ship_address)}, ${esc(o.ship_city)}, ${esc(o.ship_state)}</p>
      ${o.delivery_notes ? `<p><i>${esc(o.delivery_notes)}</i></p>` : ''}
      <p style="color:var(--mut)">${o.order_items.map(i => `${i.quantity} × ${esc(i.product_name)}`).join(', ')}</p>
      <div class="foot" style="justify-content:flex-start;flex-wrap:wrap"><a class="btn pri" style="display:inline-block;text-align:center;text-decoration:none" target="_blank" rel="noopener" href="https://www.google.com/maps/dir/?api=1&travelmode=driving&destination=${encodeURIComponent([o.ship_address, o.ship_city, o.ship_state, o.ship_country].filter(Boolean).join(', '))}">Start navigation</a><button class="btn" data-ok="${o.id}">Delivered</button><button class="btn ghost" data-fail="${o.id}">Could not deliver</button></div></div>`).join('') : '<div class="panel state">No deliveries assigned to you right now.</div>') +
    (done.length ? `<div class="panel"><h2>Recently completed</h2>${table([['Order', o => esc(o.order_number)], ['Customer', o => esc(o.ship_name)], ['Status', o => pill(o.status, 'ok')], ['Cash', o => o.cash_collected ? money(o.cash_collected) : '']], done)}</div>` : '');
  listen('click', async e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.ok) {
      const o = todo.find(x => x.id === b.dataset.ok);
      openDlg(`<h2>Confirm delivery ${esc(o.order_number)}</h2><div id="dcMsg"></div>
        ${collect(o) ? `<p>First collect <b>${money(o.total)}</b> in cash from the customer.</p>` : '<p>This order is already paid.</p>'}
        <form id="dcForm" novalidate><label for="dc_code">Customer's 4-digit delivery code</label>
          <input id="dc_code" inputmode="numeric" maxlength="4" autocomplete="one-time-code" style="font-size:1.4rem;letter-spacing:6px" required>
          <p style="color:var(--mut);font-size:13px;margin-top:6px">Ask the customer for the code. They can see it in their account and email.</p>
          <div class="foot"><button type="button" class="btn ghost" data-close>Cancel</button><button class="btn pri">Confirm delivery</button></div></form>`);
      $('#dcForm').onsubmit = async ev => {
        ev.preventDefault(); const code = $('#dc_code').value.trim();
        if (!/^\d{4}$/.test(code)) return fail('#dcMsg', 'Enter the 4-digit code.');
        const { data: res, error: err } = await db.rpc('rider_mark_delivered', { p_order: o.id, p_cash: collect(o) ? o.total : null, p_code: code });
        if (err) return fail('#dcMsg', err);
        if (res && res.ok === false) return fail('#dcMsg', res.error + (res.attempts_left != null ? ` ${res.attempts_left} attempt(s) left.` : ''));
        toast('Delivery recorded'); closeDlg(); route();
      };
      return;
    }
    if (b.dataset.fail) {
      const reason = prompt('Why could the order not be delivered?'); if (!reason) return;
      const { error: err } = await db.rpc('rider_mark_failed', { p_order: b.dataset.fail, p_reason: reason });
      err ? toast(err.message, true) : (toast('Reported. Dispatch will reassign it.'), route());
    }
  });
};

/* ---------- staff (super admin only) ---------- */
const PERMS = [['orders.view', 'View orders'], ['orders.accept', 'Accept / cancel orders'], ['orders.pack', 'Pack orders (processing)'], ['orders.ship', 'Ship and deliver orders'],
  ['orders.assign', 'Assign orders to riders (dispatch)'], ['orders.payments', 'Record payments (e.g. cash collected)'], ['products.manage', 'Manage products and categories'], ['inventory.manage', 'Manage inventory'],
  ['customers.view', 'View customers'], ['customers.manage', 'Suspend / reactivate customers'], ['reviews.moderate', 'Moderate reviews'], ['rider.deliver', 'Rider: sees and delivers own assigned orders']];
const PRESETS = {
  manager: ['Store manager (everything)', PERMS.map(p => p[0]).filter(k => k !== 'rider.deliver')],
  rider: ['Rider', ['rider.deliver']],
  order_manager: ['Order manager', ['orders.view', 'orders.accept', 'orders.payments']],
  warehouse: ['Warehouse / packer', ['orders.view', 'orders.pack', 'inventory.manage']],
  dispatcher: ['Dispatcher', ['orders.view', 'orders.ship', 'orders.assign']],
  catalog: ['Catalog editor', ['products.manage', 'inventory.manage']],
  support: ['Customer support', ['orders.view', 'customers.view', 'reviews.moderate']],
  custom: ['Custom', []],
};
routes.staff = async () => {
  const { data, error } = await db.from('profiles').select('id,full_name,email,role,status,permissions').in('role', ['store_admin', 'super_admin']).order('created_at');
  if (error) throw error;
  const access = r => r.role === 'super_admin' ? 'Everything (super admin)' : (r.permissions == null ? 'Everything except settings' : r.permissions.length ? r.permissions.map(k => PERMS.find(x => x[0] === k)?.[1] || k).join(', ') : 'No access');
  view.innerHTML = head('Staff', '<button class="btn pri" data-create="1">Create staff account</button><button class="btn" data-staff="">Add existing account</button>') +
    `<div class="panel"><p style="margin-bottom:8px;color:var(--mut)">Use <b>Create staff account</b> to make a new login (for example a rider) and choose what they may do. Use <b>Add existing account</b> if the person already signed up in the store.</p>
    ${table([['Name', r => `<b>${esc(r.full_name)}</b>`], ['Email', r => esc(r.email)], ['Role', r => pill(r.role === 'super_admin' ? 'Super admin' : 'Staff', r.role === 'super_admin' ? 'ok' : '')], ['Can do', r => `<div class="wrap">${esc(access(r))}</div>`],
      ['', r => r.role === 'super_admin' || r.id === S.me.id ? '' : `<div class="act"><button class="btn sm" data-staff="${r.id}">Edit</button><button class="btn sm ghost" data-reset="${r.id}">Reset password</button><button class="btn sm dng" data-remove="${r.id}">Remove</button></div>`]], data)}</div>`;
  listen('click', async e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.create) return staffForm(null, true);
    if (b.dataset.staff !== undefined) return staffForm(data.find(r => r.id === b.dataset.staff));
    if (b.dataset.reset) {
      const m = data.find(r => r.id === b.dataset.reset);
      const pw = prompt(`New password for ${m.full_name} (8+ characters, letters and numbers):`); if (!pw) return;
      if (!validPw(pw)) return toast('Password needs 8+ characters with letters and numbers.', true);
      try { await callStaffFn({ action: 'set_password', user_id: m.id, password: pw }); showCredentials(m.full_name, m.email, pw); } catch (err) { toast(err.message, true); }
      return;
    }
    if (b.dataset.remove && confirm('Remove staff access? They keep their customer account.')) {
      const { error: err } = await db.from('profiles').update({ role: 'customer', permissions: null }).eq('id', b.dataset.remove);
      err ? toast(err.message, true) : (toast('Staff access removed'), route());
    }
  });
};
const validPw = p => p.length >= 8 && /[A-Za-z]/.test(p) && /\d/.test(p);

/* Calls the create-staff Edge Function (the service-role key stays on the server). */
async function callStaffFn(body) {
  const { data, error } = await db.functions.invoke('create-staff', { body });
  if (error) {
    const status = error.context?.status; let msg;
    try { msg = (await error.context.json()).error; } catch { /* the reply was not JSON */ }
    if (!msg) msg = !status ? 'Could not reach the create-staff function. Check that it is deployed with exactly that name.'
      : status === 404 ? 'The create-staff function is not deployed yet.' : `The server returned an error (code ${status}). Check the function logs in Supabase.`;
    throw new Error(msg);
  }
  return data;
}

function showCredentials(name, email, password) {
  const text = `Sign-in page: ${location.origin}${location.pathname}\nEmail: ${email}\nPassword: ${password}`;
  openDlg(`<h2>Account ready</h2><p>Give these details to ${esc(name)} privately. For safety, this is the only time the password is shown.</p>
    <div class="panel" style="white-space:pre-line;word-break:break-all">${esc(text)}</div>
    <div class="foot"><button class="btn" id="copyCred">Copy details</button><button class="btn pri" data-close>Done</button></div>`);
  $('#copyCred').onclick = () => navigator.clipboard.writeText(text).then(() => toast('Copied'), () => toast('Copy failed. Select the text instead.', true));
}

function staffForm(m, create = false) {
  const cur = m?.permissions ?? PERMS.map(p => p[0]);
  openDlg(`<h2>${create ? 'Create staff account' : m ? 'Edit staff access' : 'Add existing account as staff'}</h2><div id="stMsg"></div><form id="stForm" novalidate>
    ${create ? '<div class="grid2"><div><label for="st_name">Full name</label><input id="st_name" required></div><div><label for="st_phone">Phone</label><input id="st_phone" type="tel" required></div></div>' : ''}
    <label for="st_email">Account email</label><input id="st_email" type="email" value="${esc(m?.email)}" ${m ? 'disabled' : ''} required>
    ${create ? '<label for="st_pw">Password (8+ characters, letters and numbers)</label><input id="st_pw" type="text" autocomplete="off" required>' : ''}
    <label for="st_preset">Role</label><select id="st_preset">${opts(Object.entries(PRESETS).map(([k, v]) => [k, v[0]]), m ? 'custom' : create ? 'rider' : 'order_manager')}</select>
    <div class="flags" id="st_perms" style="display:grid;grid-template-columns:1fr 1fr">${PERMS.map(([k, l]) => `<label><input type="checkbox" value="${k}"> ${l}</label>`).join('')}</div>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancel</button><button class="btn pri" id="stSave">${create ? 'Create account' : 'Save'}</button></div></form>`);
  const boxes = [...dlg.querySelectorAll('#st_perms input')];
  const setBoxes = list => boxes.forEach(b => { b.checked = list.includes(b.value); });
  setBoxes(m ? cur : create ? PRESETS.rider[1] : PRESETS.order_manager[1]);
  $('#st_preset').onchange = e => { if (e.target.value !== 'custom') setBoxes(PRESETS[e.target.value][1]); };
  $('#stForm').onsubmit = async ev => {
    ev.preventDefault();
    const perms = boxes.filter(b => b.checked).map(b => b.value);
    if (!perms.length) return fail('#stMsg', 'Choose at least one thing this person may do.');
    if (create) {
      const v = { full_name: $('#st_name').value.trim(), phone: $('#st_phone').value.trim(), email: $('#st_email').value.trim(), password: $('#st_pw').value };
      if (v.full_name.length < 2) return fail('#stMsg', 'Enter the full name.');
      if (!/^\+?[\d\s-]{7,15}$/.test(v.phone)) return fail('#stMsg', 'Enter a valid phone number.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.email)) return fail('#stMsg', 'Enter a valid email address.');
      if (!validPw(v.password)) return fail('#stMsg', 'Password needs 8+ characters with letters and numbers.');
      const btn = $('#stSave'); btn.disabled = true; btn.textContent = 'Creating…';
      try { await callStaffFn({ action: 'create', ...v, permissions: perms }); showCredentials(v.full_name, v.email, v.password); route(); }
      catch (err) { fail('#stMsg', err); btn.disabled = false; btn.textContent = 'Create account'; }
      return;
    }
    let q;
    if (m) q = db.from('profiles').update({ permissions: perms }).eq('id', m.id);
    else {
      const email = $('#st_email').value.trim();
      if (!email) return fail('#stMsg', 'Enter the staff member’s account email.');
      const { data: found } = await db.from('profiles').select('id,role').eq('email', email.toLowerCase()).maybeSingle();
      if (!found) return fail('#stMsg', 'No account with that email. Use "Create staff account" instead.');
      if (found.role === 'super_admin') return fail('#stMsg', 'That account is already a super admin.');
      q = db.from('profiles').update({ role: 'store_admin', permissions: perms }).eq('id', found.id);
    }
    const { error } = await q; if (error) return fail('#stMsg', error);
    toast('Staff access saved'); closeDlg(); route();
  };
}

/* ---------- change my own password (any staff member) ---------- */
$('#pwBtn').addEventListener('click', () => {
  openDlg(`<h2>Change password</h2><div id="pwMsg"></div><form id="pwForm" novalidate>
    <label for="pw1">New password (8+ characters, letters and numbers)</label><input id="pw1" type="password" autocomplete="new-password" required>
    <label for="pw2">Confirm new password</label><input id="pw2" type="password" autocomplete="new-password" required>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancel</button><button class="btn pri">Update password</button></div></form>`);
  $('#pwForm').onsubmit = async e => {
    e.preventDefault(); const a = $('#pw1').value;
    if (!validPw(a)) return fail('#pwMsg', 'Password needs 8+ characters with letters and numbers.');
    if (a !== $('#pw2').value) return fail('#pwMsg', 'Passwords do not match.');
    const { error } = await db.auth.updateUser({ password: a });
    if (error) return fail('#pwMsg', error);
    toast('Password updated'); closeDlg();
  };
});

/* Hide broken images (replaces an inline onerror attribute, which the strict security policy blocks). */
document.addEventListener('error', e => { if (e.target.tagName === 'IMG') e.target.style.visibility = 'hidden'; }, true);

/* ---------- start ---------- */
(async () => {
  const { data: { session } } = await db.auth.getSession();
  await enter(session?.user || null);
})();
