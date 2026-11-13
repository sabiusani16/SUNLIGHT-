'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const COLORS = ['#075B42', '#0E7C5A', '#8A6D0B', '#2F6F8F', '#6B4E9B', '#B5533C'];

let token = localStorage.getItem('sl_token'), me = null, chats = [], users = [], current = null;
let filter = 'all', query = '', pollTimer = null, sigChats = '', sigUsers = '', sigMsgs = '';
const favs = new Set(JSON.parse(localStorage.getItem('sl_favs') || '[]'));

/* ---------- API ---------- */
async function api(path, opts = {}) {
  const res = await fetch('/api/' + path, {
    method: opts.body ? 'POST' : (opts.method || 'GET'),
    headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && token && path !== 'login') logout(true);
  if (!res.ok) throw new Error(data.error || 'Something went wrong');
  return data;
}

/* ---------- Helpers ---------- */
const initials = n => n.trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();
const avatar = (p, extra = '', dot = false) =>
  `<div class="avatar ${extra}" style="background:${COLORS[p.id % COLORS.length]}"><span>${esc(initials(p.name))}</span>${dot && p.online ? '<i class="dot"></i>' : ''}</div>`;
const tickIcon = t => t ? `<i class="fa-solid fa-check-double tick ${t === 'read' ? 'read' : ''}"></i>` : '';
const clock = ts => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
function fmt(ts) {
  const d = new Date(ts), n = new Date();
  if (d.toDateString() === n.toDateString()) return clock(ts);
  if (d.toDateString() === new Date(n - 864e5).toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { day: 'numeric', month: 'short' });
}
let toastTimer;
function toast(text) {
  const t = $('#toast');
  t.textContent = text; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}
const openScreen = id => $('#' + id).classList.add('open');
const closeScreen = id => $('#' + id).classList.remove('open');
const empty = (icon, text) => `<div class="empty"><i class="${icon}"></i>${text}</div>`;

/* ---------- Auth ---------- */
let mode = 'login';
function setMode(m) {
  mode = m;
  $('#nameWrap').hidden = m === 'login';
  $('#authSub').textContent = m === 'login' ? 'Log in to continue' : 'Create your SUNLIGHT account';
  $('#authBtn').textContent = m === 'login' ? 'Log in' : 'Create account';
  $('#authSwitch').textContent = m === 'login' ? 'New here? Create an account' : 'Already have an account? Log in';
  $('#authPass').autocomplete = m === 'login' ? 'current-password' : 'new-password';
  $('#authErr').textContent = '';
}
$('#authSwitch').addEventListener('click', () => setMode(mode === 'login' ? 'register' : 'login'));
$('#authForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('#authBtn'); btn.disabled = true; $('#authErr').textContent = '';
  try {
    const d = await api(mode, { body: { name: $('#authName').value, username: $('#authUser').value, password: $('#authPass').value } });
    token = d.token; localStorage.setItem('sl_token', token);
    $('#authPass').value = '';
    await start(d.user);
  } catch (err) { $('#authErr').textContent = err.message; }
  btn.disabled = false;
});

function logout(silent) {
  if (token && !silent) api('logout', { method: 'POST', body: {} }).catch(() => {});
  token = null; me = null; current = null; chats = []; users = [];
  localStorage.removeItem('sl_token');
  clearInterval(pollTimer); sigChats = sigUsers = sigMsgs = '';
  ['chatScreen', 'newChat'].forEach(closeScreen);
  openScreen('auth'); setMode('login');
}

async function start(user) {
  me = user;
  closeScreen('auth');
  renderProfile();
  await Promise.all([loadChats(), loadUsers()]).catch(() => {});
  showView('chats');
  clearInterval(pollTimer);
  pollTimer = setInterval(poll, 4000);
}

/* ---------- Data loading ---------- */
async function loadChats() {
  const d = await api('chats');
  const next = d.chats.map(c => ({
    id: c.id, name: c.name, online: c.online, unread: c.unread, time: fmt(c.last_at), msg: c.last_body,
    tick: c.last_sender === me.id ? (c.last_read ? 'read' : 'delivered') : null
  }));
  const sig = JSON.stringify(next);
  chats = next;
  if (sig !== sigChats) { sigChats = sig; renderChats(); }
}
async function loadUsers() {
  const d = await api('users');
  const sig = JSON.stringify(d.users);
  users = d.users;
  if (sig !== sigUsers) { sigUsers = sig; renderStories(); renderLists(); }
}
function poll() {
  if (!me) return;
  loadChats().catch(() => {}); loadUsers().catch(() => {});
  if ($('#chatScreen').classList.contains('open')) loadMessages().catch(() => {});
}

/* ---------- Rendering ---------- */
function renderChats() {
  const q = query.trim().toLowerCase();
  const list = chats.filter(c =>
    (filter === 'all' || (filter === 'unread' && c.unread) || (filter === 'fav' && favs.has(c.id))) &&
    (!q || c.name.toLowerCase().includes(q) || c.msg.toLowerCase().includes(q)));
  $('#chatList').innerHTML = list.length ? list.map((c, i) => `
    <div class="row" data-id="${c.id}" style="animation-delay:${Math.min(i, 8) * 30}ms">
      ${avatar(c, '', true)}
      <div class="body">
        <div class="line"><strong>${esc(c.name)}</strong><span class="time ${c.unread ? 'new' : ''}">${esc(c.time)}</span></div>
        <div class="preview"><span class="grow">${tickIcon(c.tick)}<span class="txt">${esc(c.msg)}</span></span>
          ${favs.has(c.id) && !c.unread ? '<i class="fa-solid fa-star fav-ico"></i>' : ''}
          ${c.unread ? `<span class="badge">${c.unread}</span>` : ''}</div>
      </div>
    </div>`).join('')
    : q ? empty('fa-regular fa-comment-dots', `No chats match “${esc(query)}”`)
    : filter === 'group' ? empty('fa-solid fa-user-group', 'Groups are coming soon')
    : filter === 'fav' ? empty('fa-regular fa-star', 'Open a chat and tap the star to add a favorite')
    : filter === 'unread' ? empty('fa-solid fa-check-double', 'You’re all caught up')
    : empty('fa-regular fa-comment-dots', 'No chats yet.<br>Tap the green button to start one.');
  const total = chats.filter(c => c.unread).length;
  const pill = $('#unreadCount');
  pill.textContent = total; pill.classList.toggle('show', total > 0);
}

function renderProfile() {
  const mine = avatar(me, '');
  $('#profileCard').innerHTML = `${mine.replace('class="avatar ', 'class="avatar big ')}<div><strong>${esc(me.name)}</strong><p>@${esc(me.username)}</p></div>`;
  $('#myStatus').innerHTML = `${mine.replace('</div>', '<i class="add-badge fa-solid fa-plus"></i></div>')}<div><strong>My status</strong><p>Tap to add a status update</p></div>`;
  $('#settingsList').innerHTML = [
    ['fa-key', 'Account', '@' + me.username, 'Account'],
    ['fa-bell', 'Notifications', 'Message tones', 'Notifications'],
    ['fa-circle-question', 'Help', 'Help centre, contact us', 'Help'],
    ['fa-right-from-bracket', 'Log out', 'Sign out of this device', '__logout']
  ].map(s => `<div class="set-row" data-set="${s[3]}"><span class="set-ico"><i class="fa-solid ${s[0]}"></i></span><div><strong>${s[1]}</strong><small>${esc(s[2])}</small></div></div>`).join('');
}

function renderStories() {
  const mine = `<div class="story" data-toast="Add status"><div class="avatar" style="background:${COLORS[me.id % COLORS.length]}"><span>${esc(initials(me.name))}</span><i class="add-badge fa-solid fa-plus"></i></div><span class="n">My status</span></div>`;
  $('#stories').innerHTML = mine + users.slice(0, 10).map(u =>
    `<div class="story" data-contact="${u.id}">${avatar(u, `ring ${u.online ? '' : 'seen'}`)}<span class="n">${esc(u.name.split(' ')[0])}</span></div>`).join('');
}

function renderLists() {
  const rows = users.map(u => `
    <div class="row" data-contact="${u.id}">${avatar(u, '', true)}
      <div class="body"><div class="line"><strong>${esc(u.name)}</strong></div>
      <div class="preview">${u.online ? 'Online' : '@' + esc(u.username)}</div></div></div>`).join('');
  const none = empty('fa-solid fa-user-plus', 'No contacts yet.<br>Ask a friend to create a SUNLIGHT account.');
  $('#contactList').innerHTML = rows || none;
  $('#updateList').innerHTML = users.length ? users.map(u => `
    <div class="row" data-toast="${esc(u.name)} has no new status">${avatar(u, `ring ${u.online ? '' : 'seen'}`)}
    <div class="body"><div class="line"><strong>${esc(u.name)}</strong></div><div class="preview">No recent updates</div></div></div>`).join('') : none;
  $('#contactCount').textContent = `${users.length} contact${users.length === 1 ? '' : 's'}`;
}
$('#communityList').innerHTML = empty('fa-solid fa-users', 'Communities are coming soon');
$('#callList').innerHTML = empty('fa-solid fa-phone', 'Voice and video calls are coming soon');

/* ---------- Navigation ---------- */
function showView(name) {
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  $('#fab').classList.toggle('hide', name !== 'chats');
  $('#main').scrollTop = 0;
  if (name !== 'chats') closeSearch();
}
$('#bottomNav').addEventListener('click', e => { const b = e.target.closest('.nav-item'); if (b) showView(b.dataset.view); });
$('#tabs').addEventListener('click', e => {
  const t = e.target.closest('.tab'); if (!t) return;
  $$('.tab').forEach(x => x.classList.toggle('active', x === t));
  filter = t.dataset.filter; renderChats();
});

/* ---------- Search ---------- */
function closeSearch() {
  $('#searchbar').classList.remove('open');
  $('#searchInput').value = ''; query = ''; if (me) renderChats();
}
$('#searchBtn').addEventListener('click', () => {
  showView('chats');
  const bar = $('#searchbar');
  if (bar.classList.contains('open')) return closeSearch();
  bar.classList.add('open');
  setTimeout(() => $('#searchInput').focus(), 250);
});
$('#searchClose').addEventListener('click', closeSearch);
$('#searchInput').addEventListener('input', e => { query = e.target.value; renderChats(); });

/* ---------- Menu ---------- */
const menu = $('#menu');
$('#menuBtn').addEventListener('click', e => { e.stopPropagation(); menu.classList.toggle('open'); });
document.addEventListener('click', e => { if (!menu.contains(e.target)) menu.classList.remove('open'); });
$('#cameraBtn').addEventListener('click', () => toast('Camera is not available yet'));

function action(act) {
  menu.classList.remove('open');
  if (act === 'settings') { closeScreen('newChat'); showView('settings'); }
  else toast({ group: 'Groups are coming soon', star: 'No starred messages yet', devices: 'No linked devices', contact: 'Contacts appear when friends join', community: 'Communities are coming soon' }[act] || act);
}
$$('[data-act]').forEach(el => el.addEventListener('click', () => action(el.dataset.act)));

document.addEventListener('click', e => {
  const t = e.target.closest('[data-toast]'); if (t) toast(t.dataset.toast);
  const c = e.target.closest('[data-close]'); if (c) closeScreen(c.dataset.close);
  const s = e.target.closest('[data-set]');
  if (s) s.dataset.set === '__logout' ? logout() : toast(s.dataset.set);
});
$('#fab').addEventListener('click', () => { loadUsers().catch(() => {}); openScreen('newChat'); });

/* ---------- Conversation ---------- */
const bubble = m => {
  const out = m.sender_id === me.id;
  return `<div class="msg ${out ? 'out' : 'in'}">${esc(m.body)}<small>${clock(m.created_at)}${out ? tickIcon(m.read_at ? 'read' : 'delivered') : ''}</small></div>`;
};
const scrollDown = () => { const m = $('#messages'); m.scrollTop = m.scrollHeight; };
const updateFav = () => { $('#favBtn i').className = (current && favs.has(current.id) ? 'fa-solid' : 'fa-regular') + ' fa-star'; };

function openChat(id) {
  const p = users.find(u => u.id === +id) || chats.find(c => c.id === +id); if (!p) return;
  current = p; sigMsgs = '';
  $('#chatAvatar').outerHTML = avatar(p, 'sm').replace('class="avatar sm"', 'class="avatar sm" id="chatAvatar"');
  $('#chatName').textContent = p.name;
  $('#chatState').textContent = p.online ? 'online' : 'offline';
  $('#messages').innerHTML = '';
  updateFav(); openScreen('chatScreen'); closeScreen('newChat');
  loadMessages(true).then(loadChats).catch(err => toast(err.message));
}
async function loadMessages(force) {
  if (!current) return;
  const who = current;
  const d = await api('messages?with=' + who.id);
  if (current !== who) return;
  const sig = d.messages.map(m => m.id + (m.read_at ? 'r' : '')).join();
  $('#chatState').textContent = d.online ? 'online' : 'offline';
  if (!force && sig === sigMsgs) return;
  sigMsgs = sig;
  const box = $('#messages'), near = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  let lastDay = '';
  box.innerHTML = d.messages.length ? d.messages.map(m => {
    const day = new Date(m.created_at).toDateString(); let h = '';
    if (day !== lastDay) { lastDay = day; h = `<div class="day">${day === new Date().toDateString() ? 'Today' : new Date(m.created_at).toLocaleDateString([], { day: 'numeric', month: 'short' })}</div>`; }
    return h + bubble(m);
  }).join('') : '<div class="day">Say hello 👋</div>';
  if (force || near) scrollDown();
}

$('#chatList').addEventListener('click', e => { const r = e.target.closest('[data-id]'); if (r) openChat(r.dataset.id); });
document.addEventListener('click', e => { const r = e.target.closest('[data-contact]'); if (r) openChat(r.dataset.contact); });
$('#favBtn').addEventListener('click', () => {
  if (!current) return;
  favs.has(current.id) ? favs.delete(current.id) : favs.add(current.id);
  localStorage.setItem('sl_favs', JSON.stringify([...favs]));
  updateFav(); renderChats();
  toast(favs.has(current.id) ? 'Added to favorites' : 'Removed from favorites');
});
$('#composer').addEventListener('submit', async e => {
  e.preventDefault();
  const input = $('#msgInput'), body = input.value.trim();
  if (!body || !current) return;
  input.value = '';
  try {
    await api('messages', { body: { to: current.id, body } });
    await loadMessages(true); loadChats();
  } catch (err) { toast(err.message); input.value = body; }
});

/* ---------- Init ---------- */
setMode('login');
if (token) api('me').then(d => start(d.user)).catch(() => logout(true));
