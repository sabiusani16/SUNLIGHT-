'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const pic = n => `https://i.pravatar.cc/150?img=${n}`;

/* ---------- Sample data ---------- */
const chats = [
  { id: 1, name: 'Amina Yusuf', img: 5, msg: 'Sending the photos now 📸', time: '10:42', unread: 3, online: true, fav: true, tick: null, story: 'new' },
  { id: 2, name: 'Design Team', img: 0, msg: 'Hassan: Final mockups are approved ✅', time: '10:15', unread: 12, online: false, group: true, tick: null },
  { id: 3, name: 'Omar Farooq', img: 12, msg: 'See you at the café at 6', time: '09:58', unread: 0, online: true, tick: 'read', story: 'new' },
  { id: 4, name: 'Mum', img: 47, msg: 'Don’t forget to eat something', time: '09:30', unread: 1, online: false, fav: true, tick: null },
  { id: 5, name: 'Sara Malik', img: 9, msg: 'That sounds perfect, thank you!', time: 'Yesterday', unread: 0, online: false, tick: 'delivered', story: 'seen' },
  { id: 6, name: 'Weekend Hikers', img: 0, msg: 'Bilal: Trail opens at 7 sharp', time: 'Yesterday', unread: 5, online: false, group: true, tick: null },
  { id: 7, name: 'Daniel Brooks', img: 15, msg: 'Invoice sent, let me know', time: 'Yesterday', unread: 0, online: true, tick: 'read', story: 'seen' },
  { id: 8, name: 'Zainab Ali', img: 32, msg: '🎉 Congratulations!', time: 'Tuesday', unread: 0, online: false, fav: true, tick: 'read' },
  { id: 9, name: 'Family Circle', img: 0, msg: 'Dad: Dinner at 8 on Friday', time: 'Monday', unread: 0, online: false, group: true, tick: 'delivered' },
  { id: 10, name: 'Ibrahim Khan', img: 53, msg: 'Voice message (0:24)', time: 'Sunday', unread: 0, online: false, tick: 'read' }
];
const communities = [
  { name: 'Sunrise Neighbours', sub: '4 groups · 238 members', img: 0 },
  { name: 'Web Developers Hub', sub: '6 groups · 1,204 members', img: 0 },
  { name: 'Book Lovers Club', sub: '3 groups · 512 members', img: 0 }
];
const calls = [
  { name: 'Amina Yusuf', img: 5, info: 'Today, 09:12', icon: 'fa-arrow-down-left', miss: true, type: 'fa-phone' },
  { name: 'Omar Farooq', img: 12, info: 'Today, 08:30', icon: 'fa-arrow-up-right', type: 'fa-video' },
  { name: 'Mum', img: 47, info: 'Yesterday, 20:05', icon: 'fa-arrow-down-left', type: 'fa-phone' },
  { name: 'Daniel Brooks', img: 15, info: 'Yesterday, 14:47', icon: 'fa-arrow-up-right', type: 'fa-phone' },
  { name: 'Sara Malik', img: 9, info: 'Tuesday, 18:20', icon: 'fa-arrow-down-left', miss: true, type: 'fa-video' }
];
const settings = [
  ['fa-key', 'Account', 'Privacy, security, change number'],
  ['fa-lock', 'Privacy', 'Last seen, profile photo, status'],
  ['fa-bell', 'Notifications', 'Message, group and call tones'],
  ['fa-database', 'Storage and data', 'Network usage, auto-download'],
  ['fa-palette', 'Appearance', 'Theme, wallpaper, chat colour'],
  ['fa-circle-question', 'Help', 'Help centre, contact us']
];
const history = {};
const replies = ['Sounds good!', 'Got it 👍', 'Give me a minute', 'Haha, really?', 'Let’s do it', 'Talk soon ☀️'];

/* ---------- Helpers ---------- */
const initials = n => n.split(' ').map(w => w[0]).slice(0, 2).join('').toUpperCase();
const avatar = (p, extra = '', dot = false) =>
  `<div class="avatar ${extra}">${p.img ? `<img src="${pic(p.img)}" alt="" loading="lazy" onerror="this.remove()">` : ''}<span>${initials(p.name)}</span>${dot && p.online ? '<i class="dot"></i>' : ''}</div>`;
const tickIcon = t => t ? `<i class="fa-solid fa-check-double tick ${t === 'read' ? 'read' : ''}"></i>` : '';
const nowTime = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });

let toastTimer;
function toast(text) {
  const t = $('#toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

/* ---------- Chat list ---------- */
let filter = 'all', query = '';

function renderChats() {
  const q = query.trim().toLowerCase();
  const list = chats.filter(c =>
    (filter === 'all' || (filter === 'unread' && c.unread) || (filter === 'fav' && c.fav) || (filter === 'group' && c.group)) &&
    (!q || c.name.toLowerCase().includes(q) || c.msg.toLowerCase().includes(q)));
  $('#chatList').innerHTML = list.length ? list.map((c, i) => `
    <div class="row" data-id="${c.id}" style="animation-delay:${i * 30}ms">
      ${avatar(c, '', true)}
      <div class="body">
        <div class="line"><strong>${c.name}</strong><span class="time ${c.unread ? 'new' : ''}">${c.time}</span></div>
        <div class="preview"><span class="grow">${tickIcon(c.tick)}<span class="txt">${c.msg}</span></span>
          ${c.fav && !c.unread ? '<i class="fa-solid fa-star fav-ico"></i>' : ''}
          ${c.unread ? `<span class="badge">${c.unread}</span>` : ''}</div>
      </div>
    </div>`).join('')
    : `<div class="empty"><i class="fa-regular fa-comment-dots"></i>${q ? `No chats match “${query}”` : 'No chats here yet'}</div>`;
  const total = chats.filter(c => c.unread).length;
  const pill = $('#unreadCount');
  pill.textContent = total;
  pill.classList.toggle('show', total > 0);
}

function renderStories() {
  const my = `<div class="story" data-toast="Add status"><div class="avatar" style="background:#E4EEE9">
      <img src="${pic(47)}" alt="" onerror="this.remove()"><span>Y</span><i class="add-badge fa-solid fa-plus"></i></div><span class="n">My status</span></div>`;
  const others = chats.filter(c => c.story).map(c => `
    <div class="story" data-id="${c.id}">${avatar(c, `ring ${c.story === 'seen' ? 'seen' : ''}`)}<span class="n">${c.name.split(' ')[0]}</span></div>`).join('');
  $('#stories').innerHTML = my + others;
}

/* ---------- Other views ---------- */
function renderViews() {
  $('#myStatus').innerHTML = `<div class="avatar" style="background:#E4EEE9"><img src="${pic(47)}" alt="" onerror="this.remove()"><span>Y</span><i class="add-badge fa-solid fa-plus"></i></div>
    <div><strong>My status</strong><p>Tap to add a status update</p></div>`;
  $('#updateList').innerHTML = chats.filter(c => c.story).map(c => `
    <div class="row" data-toast="Viewing ${c.name}'s status">${avatar(c, `ring ${c.story === 'seen' ? 'seen' : ''}`)}
    <div class="body"><div class="line"><strong>${c.name}</strong></div><div class="preview">${c.time === 'Yesterday' ? 'Yesterday' : 'Today'}, ${c.time.includes(':') ? c.time : '18:20'}</div></div></div>`).join('');
  $('#communityList').innerHTML = communities.map(c => `
    <div class="row" data-toast="Opening ${c.name}">${avatar(c, '')}
    <div class="body"><div class="line"><strong>${c.name}</strong></div><div class="preview">${c.sub}</div></div></div>`).join('');
  $('#callList').innerHTML = calls.map(c => `
    <div class="row ${c.miss ? 'missed' : ''}" data-toast="Calling ${c.name}">${avatar(c, '')}
    <div class="body"><div class="line"><strong>${c.name}</strong><i class="fa-solid ${c.type} call-btn"></i></div>
    <div class="preview"><i class="fa-solid ${c.icon} tick" style="color:${c.miss ? '#D64545' : '#2DCB73'}"></i><span class="txt">${c.info}</span></div></div></div>`).join('');
  $('#settingsList').innerHTML = settings.map(s => `
    <div class="set-row" data-toast="${s[1]}"><span class="set-ico"><i class="fa-solid ${s[0]}"></i></span>
    <div><strong>${s[1]}</strong><small>${s[2]}</small></div></div>`).join('');
  $('#contactList').innerHTML = chats.filter(c => !c.group).sort((a, b) => a.name.localeCompare(b.name)).map(c => `
    <div class="row" data-contact="${c.id}">${avatar(c, '', true)}
    <div class="body"><div class="line"><strong>${c.name}</strong></div><div class="preview">${c.online ? 'Online' : 'Hey there! I am using SUNLIGHT'}</div></div></div>`).join('');
  $('#contactCount').textContent = `${chats.filter(c => !c.group).length} contacts`;
}

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
  filter = t.dataset.filter;
  renderChats();
});

/* ---------- Search ---------- */
function closeSearch() {
  $('#searchbar').classList.remove('open');
  $('#searchInput').value = ''; query = ''; renderChats();
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
$('#cameraBtn').addEventListener('click', () => toast('Camera is not available in this demo'));

function action(act) {
  menu.classList.remove('open');
  if (act === 'settings') { closeScreen('newChat'); showView('settings'); }
  else toast({ group: 'New group', star: 'No starred messages yet', devices: 'Linked devices', contact: 'New contact', community: 'New community' }[act] || act);
}
$$('[data-act]').forEach(el => el.addEventListener('click', () => action(el.dataset.act)));

/* generic delegated handlers */
document.addEventListener('click', e => {
  const t = e.target.closest('[data-toast]'); if (t) toast(t.dataset.toast);
  const c = e.target.closest('[data-close]'); if (c) closeScreen(c.dataset.close);
});

/* ---------- Screens ---------- */
const openScreen = id => $('#' + id).classList.add('open');
const closeScreen = id => $('#' + id).classList.remove('open');
$('#fab').addEventListener('click', () => openScreen('newChat'));

/* ---------- Conversation ---------- */
let current = null;

function seed(c) {
  history[c.id] = [
    { out: false, text: 'Hey! How’s your day going?', t: '09:40' },
    { out: true, text: 'Pretty good, just wrapping up some work ☀️', t: '09:41', tick: 'read' },
    { out: false, text: c.msg.replace(/^[^:]+: /, ''), t: c.time.includes(':') ? c.time : '09:45' }
  ];
}
function bubble(m) {
  return `<div class="msg ${m.out ? 'out' : 'in'}">${m.text}<small>${m.t}${m.out ? tickIcon(m.tick) : ''}</small></div>`;
}
function openChat(id) {
  const c = chats.find(x => x.id === +id); if (!c) return;
  current = c; c.unread = 0;
  if (!history[c.id]) seed(c);
  $('#chatAvatar').outerHTML = avatar(c, 'sm').replace('class="avatar sm"', 'class="avatar sm" id="chatAvatar"');
  $('#chatName').textContent = c.name;
  $('#chatState').textContent = c.group ? 'tap here for group info' : c.online ? 'online' : 'last seen recently';
  $('#messages').innerHTML = '<div class="day">Today</div>' + history[c.id].map(bubble).join('');
  openScreen('chatScreen'); closeScreen('newChat');
  scrollDown(); renderChats();
}
const scrollDown = () => { const m = $('#messages'); m.scrollTop = m.scrollHeight; };

$('#chatList').addEventListener('click', e => { const r = e.target.closest('.row[data-id]'); if (r) openChat(r.dataset.id); });
$('#stories').addEventListener('click', e => { const s = e.target.closest('.story[data-id]'); if (s) toast('Viewing status'); });
$('#contactList').addEventListener('click', e => { const r = e.target.closest('[data-contact]'); if (r) openChat(r.dataset.contact); });

$('#composer').addEventListener('submit', e => {
  e.preventDefault();
  const input = $('#msgInput'), text = input.value.trim();
  if (!text || !current) return;
  const c = current, m = { out: true, text: '', t: nowTime(), tick: 'delivered' };
  m.text = text.replace(/[&<>]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch]));
  history[c.id].push(m);
  $('#messages').insertAdjacentHTML('beforeend', bubble(m));
  input.value = ''; scrollDown();
  c.msg = text; c.time = m.t; c.tick = 'delivered'; renderChats();

  const typing = document.createElement('div');
  typing.className = 'typing'; typing.innerHTML = '<i></i><i></i><i></i>';
  setTimeout(() => { if (current === c) { $('#messages').appendChild(typing); scrollDown(); } }, 500);
  setTimeout(() => {
    typing.remove();
    const r = { out: false, text: replies[Math.floor(Math.random() * replies.length)], t: nowTime() };
    history[c.id].push(r); m.tick = 'read';
    if (current === c && $('#chatScreen').classList.contains('open')) {
      $('#messages').insertAdjacentHTML('beforeend', bubble(r)); scrollDown();
    } else c.unread++;
    c.msg = r.text; c.time = r.t; c.tick = null; renderChats();
  }, 1900);
});

/* ---------- Init ---------- */
renderChats(); renderStories(); renderViews(); showView('chats');
