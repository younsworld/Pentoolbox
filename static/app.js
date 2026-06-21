
// ── STATE ─────────────────────────────────────────────────────────────────
const ST = {
  user: null,
  token: null,
  role: null,  // "admin" ou "analyst"
  stats: { vulns:0, scans:0, reports:0, hosts:0 },
  activity: [],
  lastExploit: null,
  openvasJobId: null,  // job OpenVAS en cours (pour l'arrêt via GMP stop_task)
  johnJobId: null,     // job John the Ripper en cours (polling)
  sessionId: null,     // session Metasploit sélectionnée dans la console
};

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── DIALOGUES STYLISÉS ─────────────────────────────────────────────────────
// Remplacent alert()/confirm()/prompt() natifs (qui affichent l'origine
// "localhost" dans la barre de titre et ne respectent pas le thème sombre).
// Renvoient des Promises : uiAlert -> void, uiConfirm -> bool, uiPrompt -> string|null.
function _uiDialog(opts) {
  return new Promise(function(resolve) {
    var ov = document.getElementById('ui-dialog-overlay');
    if (!ov) {
      ov = document.createElement('div');
      ov.id = 'ui-dialog-overlay';
      ov.className = 'modal-overlay';
      document.body.appendChild(ov);
    }
    var danger = !!opts.danger;
    var icon = opts.danger ? 'icon-alert-triangle' : (opts.icon || 'icon-info');
    var isPrompt = opts.type === 'prompt';
    var isConfirm = opts.type === 'confirm';
    var cancelBtn = (isPrompt || isConfirm)
      ? '<button class="btn btn-ghost" id="ui-dialog-cancel">' + (opts.cancelText || 'Annuler') + '</button>'
      : '';
    var okClass = danger ? 'btn btn-danger' : 'btn btn-primary';
    ov.innerHTML =
      '<div class="modal ui-dialog">' +
        '<div class="ui-dialog-head">' +
          '<div class="ui-dialog-icon ' + (danger ? 'danger' : '') + '"><svg class="icon"><use href="#' + icon + '"/></svg></div>' +
          '<div class="ui-dialog-title">' + (opts.title || (danger ? 'Confirmation' : 'Information')) + '</div>' +
        '</div>' +
        '<div class="ui-dialog-msg">' + _esc(opts.message || '') + '</div>' +
        (isPrompt ? '<input class="ui-dialog-input" id="ui-dialog-input" type="text">' : '') +
        '<div class="ui-dialog-actions">' + cancelBtn +
          '<button class="' + okClass + '" id="ui-dialog-ok">' + (opts.okText || 'OK') + '</button>' +
        '</div>' +
      '</div>';
    ov.classList.add('open');
    var input = document.getElementById('ui-dialog-input');
    if (input && opts.defaultValue != null) input.value = opts.defaultValue;

    function cleanup(val) {
      ov.classList.remove('open');
      document.removeEventListener('keydown', onKey);
      resolve(val);
    }
    function onOk() { cleanup(isPrompt ? (input ? input.value : '') : true); }
    function onCancel() { cleanup(isPrompt ? null : false); }
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); onCancel(); }
      else if (e.key === 'Enter' && (isPrompt || !input)) { e.preventDefault(); onOk(); }
    }
    document.getElementById('ui-dialog-ok').onclick = onOk;
    var cb = document.getElementById('ui-dialog-cancel');
    if (cb) cb.onclick = onCancel;
    ov.onclick = function(e) { if (e.target === ov) onCancel(); };
    document.addEventListener('keydown', onKey);
    setTimeout(function() { (input || document.getElementById('ui-dialog-ok')).focus(); }, 30);
  });
}
function _esc(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function uiAlert(message, opts)   { return _uiDialog(Object.assign({type:'alert', message:message}, opts || {})); }
function uiConfirm(message, opts) { return _uiDialog(Object.assign({type:'confirm', danger:true, message:message}, opts || {})); }
function uiPrompt(message, defaultValue, opts) { return _uiDialog(Object.assign({type:'prompt', message:message, defaultValue:defaultValue}, opts || {})); }

// ── API FETCH avec token ──────────────────────────────────────────────────
async function apiFetch(url, options) {
  options = options || {};
  var headers = Object.assign({'Content-Type': 'application/json'}, options.headers || {});
  if (ST.token) headers['Authorization'] = 'Bearer ' + ST.token;
  var res = await fetch(url, Object.assign({}, options, { headers: headers, credentials: 'include' }));
  return res;
}

// ── LOGIN ─────────────────────────────────────────────────────────────────
function doLogin() {
  var u = document.getElementById('username').value.trim();
  var p = document.getElementById('password').value;
  var err = document.getElementById('login-error');
  var btn = document.getElementById('login-btn');

  if (!u || !p) {
    err.style.display = 'flex';
    document.getElementById('login-error-text').textContent = 'Remplis les deux champs';
    return;
  }

  btn.textContent = 'Connexion...';
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  err.style.display = 'none';

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/login', true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.withCredentials = true;
  xhr.timeout = 8000;

  xhr.onload = function() {
    btn.textContent = 'ACCÉDER À LA PLATEFORME';
    btn.disabled = false;
    try {
      var data = JSON.parse(xhr.responseText);
      if (data.ok) {
        ST.user = data.user;
        ST.token = data.token || '';
        ST.role = data.role || 'analyst';
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('app').style.display = 'block';
        document.getElementById('user-display-name').textContent = data.user;
        applyRBAC(ST.role);
        loadSysInfo();
        loadReportCount();
        loadDashboardStats();
        startSessionCountPolling();
        loadMsfModules();
        loadExploitModules();
        loadOpenVASPortLists();
        loadHydraWordlists();
        loadSqlmapTampers();
      } else {
        err.style.display = 'flex';
        document.getElementById('login-error-text').textContent = data.error || 'Identifiants incorrects';
        document.getElementById('password').value = '';
      }
    } catch(e) {
      err.style.display = 'flex';
      document.getElementById('login-error-text').textContent = 'Erreur serveur: ' + xhr.responseText.substring(0, 100);
    }
  };

  xhr.onerror = function() {
    btn.textContent = 'ACCÉDER À LA PLATEFORME';
    btn.disabled = false;
    err.style.display = 'flex';
    document.getElementById('login-error-text').textContent = 'Flask ne répond pas — relance python app.py';
  };

  xhr.ontimeout = function() {
    btn.textContent = 'ACCÉDER À LA PLATEFORME';
    btn.disabled = false;
    err.style.display = 'flex';
    document.getElementById('login-error-text').textContent = 'Timeout — Flask trop lent à répondre';
  };

  xhr.send(JSON.stringify({username: u, password: p}));
}

function doLogout() {
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/logout', true);
  xhr.onload = function() { location.reload(); };
  xhr.onerror = function() { location.reload(); };
  xhr.send();
}

document.getElementById('password').addEventListener('keydown', function(e) { if(e.key==='Enter') doLogin(); });
document.getElementById('username').addEventListener('keydown', function(e) { if(e.key==='Enter') document.getElementById('password').focus(); });
initCharts(); // configure les défauts Chart.js (thème sombre) au chargement

// ── NAV ──────────────────────────────────────────────────────────────────
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  var page = document.getElementById('page-' + name);
  if (page) page.classList.add('active');
  if (el) el.classList.add('active');
  if (window.innerWidth <= 880) closeSidebar();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('open');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('open');
}

function toggleCheck(el, ev) {
  if (el.classList.contains('disabled')) return; // module indisponible (script NSE manquant)
  // L'<input> est un DESCENDANT du <label onclick>: un clic sur le label declenche
  // aussi l'activation native du controle (clic synthetique sur l'input qui
  // re-bubble jusqu'au label), ce qui rappelle toggleCheck une 2e fois et ANNULE
  // le toggle (double-fire -> aucune case ne pouvait etre cochee, sauf HTTP deja
  // pre-coche). On annule l'activation native pour ne basculer qu'une seule fois.
  if (ev) ev.preventDefault();
  el.classList.toggle('checked');
  el.querySelector('input').checked = el.classList.contains('checked');
}

// Interroge /api/exploit/modules et désactive dans l'UI les services dont les
// scripts NSE sont absents de ce système (motif affiché au survol), au lieu de
// proposer un module qui échouerait côté nmap.
async function loadExploitModules() {
  var group = document.getElementById('exploit-modules');
  if (!group) return;
  try {
    var res = await apiFetch('/api/exploit/modules');
    if (!res.ok) return;
    var mods = await res.json();
    group.querySelectorAll('.checkbox-item').forEach(function(item) {
      var input = item.querySelector('input');
      if (!input) return;
      var info = mods[input.value];
      if (info && info.available === false) {
        item.classList.add('disabled', 'unavailable');
        item.classList.remove('checked');
        input.checked = false;
        input.disabled = true;
        item.style.opacity = '0.4';
        item.style.cursor = 'not-allowed';
        item.title = 'Non disponible — script NSE manquant: ' + (info.missing || []).join(', ');
        if (!item.querySelector('.nse-missing-tag')) {
          var tag = document.createElement('span');
          tag.className = 'nse-missing-tag';
          tag.style.cssText = 'font-size:10px;color:var(--text3);font-style:italic;margin-left:4px';
          tag.textContent = '(NSE manquant)';
          item.appendChild(tag);
        }
      } else {
        item.classList.remove('disabled', 'unavailable');
        input.disabled = false;
        item.style.opacity = '';
        item.style.cursor = '';
        item.title = '';
        var t = item.querySelector('.nse-missing-tag');
        if (t) t.remove();
      }
    });
  } catch(e) { /* page exploit non visible / API indispo — pas bloquant */ }
}

// ── TERMINAL ──────────────────────────────────────────────────────────────
// Échappe le HTML avant injection via innerHTML (noms d'utilisateur, cibles…)
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── CLASSIFICATION DES LIGNES DE LOG (BUG 4) ─────────────────────────────────
// Colorise chaque ligne selon sa nature, de façon cohérente pour TOUS les outils
// (Hydra, Metasploit, nmap, SQLMap, Nikto, exploit-auto, John, OpenVAS) :
//   🟢 SUCCESS (vert + gras) : identifiants trouvés, session ouverte, vuln
//      confirmée, hash cassé, fichier extrait — un gain actionnable.
//   🔴 ERROR (rouge) : échecs de connexion/auth, erreurs de parsing.
//   🟡 WARNING (orange) : timeouts, retries, cible non vulnérable, partiel.
//   ⚪ INFO (défaut/accent) : tout le reste.
// isHighValueWin() repère les SUCCESS majeurs -> bannière de notification.
// NB : on évite un bare /vulnerable/i qui matcherait "NOT ... vulnerable".
// Les vrais signaux de vuln confirmée : "State: VULNERABLE" (nmap NSE),
// "VULNERABLE:" (en-tête NSE), "is vulnerable" (sqlmap/divers).
var _RE_WIN = /(\bhost:\s*\S+.*\blogin:\s*\S+.*\bpassword:)|(\[\+\]\s*Session ouverte)|(session\s+#?\d+\s+opened)|(Command shell session)|(Meterpreter session)|(\bcracked\b)|(mot de passe (trouv|cass))|(Backdoor service has been spawned)|(\bUID:\s*uid=)|(\bis vulnerable\b)|(\binjectable\b)|(appears? to be injectable)|(vuln[ée]rabilit[ée] confirm)|(State:\s*VULNERABLE)|(VULNERABLE:)|(extracted to|dumped to)/i;
var _RE_OK   = /^\s*\[\+\]|^\s*\[✓\]|\bopen\b|\bfound\b|\bhost is up\b|\bgranted\b|\bsuccess(ful)?\b|\bréussi/i;
var _RE_ERR  = /^\s*\[[-!]\]|\b(error|erreur|failed|échec|echec|refused|refus(é|e)|denied|unreachable|injoignable|no route|connection (reset|closed)|parse error|traceback|fatal)\b/i;
var _RE_WARN = /^\s*\[~\]|\b(warning|avertissement|retry|retrying|partial|partiel|skipped|missing|absent|deprecated|déprécié|timed? ?out|timeout|not vulnerable|does NOT appear|aucune? (session|vuln))\b/i;

function isHighValueWin(line) { return _RE_WIN.test(line); }

function classifyLogLine(line) {
  if (_RE_WIN.test(line))  return 't-ok t-success';
  if (_RE_ERR.test(line))  return 't-err';
  if (_RE_WARN.test(line)) return 't-warn';
  if (_RE_OK.test(line))   return 't-ok';
  if (/^\s*\[\*\]/.test(line)) return 't-info';
  if (/\d+\/(tcp|udp)\s+open/i.test(line)) return 't-port';
  return 't-dim';
}

var _termWinSig = {}; // dédup des bannières par terminal (évite le spam au polling)
function termSet(id, text) {
  var t = document.getElementById(id);
  t.innerHTML = '';
  if (!text) { _termWinSig[id] = ''; return; }
  var wins = [];
  text.split('\n').forEach(function(line) {
    var d = document.createElement('div');
    d.textContent = line;
    d.className = classifyLogLine(line);
    if (isHighValueWin(line)) wins.push(line.trim());
    t.appendChild(d);
  });
  t.scrollTop = t.scrollHeight;
  // Bannière : seulement si de NOUVEAUX gains apparaissent (signature changée),
  // pour ne pas re-flasher à chaque tick de polling sur la même sortie.
  var sig = wins.join('|');
  if (wins.length && sig !== _termWinSig[id]) {
    notify(wins.length === 1 ? wins[0] : (wins.length + ' découvertes — ' + wins[0]), 'success');
  }
  _termWinSig[id] = sig;
}

// ── BANNIÈRE DE NOTIFICATION (toast) ─────────────────────────────────────────
// Signale brièvement un événement important (succès/erreur/info) même si
// l'utilisateur ne fixe pas le terminal. Thème sombre, auto-disparition.
function notify(message, type) {
  type = type || 'info';
  var stack = document.getElementById('notify-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'notify-stack';
    document.body.appendChild(stack);
  }
  var icon = type === 'success' ? 'icon-check' : type === 'error' ? 'icon-alert-triangle' : 'icon-info';
  var el = document.createElement('div');
  el.className = 'notify-toast notify-' + type;
  el.innerHTML = '<svg class="icon" style="width:18px;height:18px;flex-shrink:0"><use href="#' + icon + '"/></svg>' +
                 '<div class="notify-msg">' + escapeHtml(String(message)) + '</div>';
  stack.appendChild(el);
  requestAnimationFrame(function(){ el.classList.add('show'); });
  setTimeout(function() {
    el.classList.remove('show');
    setTimeout(function(){ if (el.parentNode) el.parentNode.removeChild(el); }, 350);
  }, 5500);
  el.onclick = function() { el.classList.remove('show'); setTimeout(function(){ if(el.parentNode) el.parentNode.removeChild(el); }, 350); };
}

// Ajoute des lignes à un terminal sans effacer l'existant (console de session).
function termAppend(id, text) {
  var t = document.getElementById(id);
  if (!t) return;
  var ph = t.querySelector('.terminal-ph');
  if (ph) t.innerHTML = '';
  (text == null ? '' : String(text)).split('\n').forEach(function(line) {
    var d = document.createElement('div');
    d.textContent = line;
    // Le prompt "$ cmd" reste en info ; le reste passe par le classifieur central.
    d.className = /^\$ /.test(line) ? 't-info' : classifyLogLine(line);
    t.appendChild(d);
  });
  t.scrollTop = t.scrollHeight;
}

function progressStart(pbId, fillId, dur) {
  var pb = document.getElementById(pbId);
  var fill = document.getElementById(fillId);
  pb.style.display = 'block'; fill.style.width='0%';
  var i=0; var steps=30;
  var iv = setInterval(function() { i++; fill.style.width=(i/steps*90)+'%'; if(i>=steps) clearInterval(iv); }, dur/steps);
  return function() { clearInterval(iv); fill.style.width='100%'; setTimeout(function(){pb.style.display='none';},500); };
}

function addActivity(icon, text, color) {
  ST.activity.unshift({icon:icon, text:text, color:color, time:new Date().toLocaleTimeString('fr-FR')});
  if (ST.activity.length > 10) ST.activity.pop();
  var el = document.getElementById('recent-activity');
  el.innerHTML = ST.activity.map(function(a) {
    return '<div class="recent-item"><div class="ri-dot" style="background:'+a.color+'"></div><svg class="icon" style="width:14px;height:14px;color:'+a.color+'"><use href="#icon-'+a.icon+'"/></svg><div style="font-size:12px;font-family:var(--sans);font-weight:500;flex:1">'+escapeHtml(a.text)+'</div><div style="font-size:11px;color:var(--text3);font-family:var(--mono)">'+a.time+'</div></div>';
  }).join('');
  saveDashboardStats();
}

function countUpTo(el, target, duration) {
  if (!el) return;
  target = target || 0;
  if (typeof prefersReducedMotion === 'function' && prefersReducedMotion()) { el.textContent = target; return; }
  var start = parseInt(el.textContent, 10) || 0;
  if (start === target) { el.textContent = target; return; }
  var t0 = performance.now();
  function tick(now) {
    var p = Math.min(1, (now - t0) / duration);
    var eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = target;
  }
  requestAnimationFrame(tick);
}

function updateDashboard() {
  countUpTo(document.getElementById('dash-vulns'), ST.stats.vulns, 600);
  countUpTo(document.getElementById('dash-scans'), ST.stats.scans, 600);
  countUpTo(document.getElementById('dash-reports'), ST.stats.reports, 600);
  countUpTo(document.getElementById('dash-hosts'), ST.stats.hosts, 600);
  // Resynchronise le compteur de rapports sur la vérité serveur : couvre aussi
  // les rapports créés AUTOMATIQUEMENT par un scan (nmap/openvas/msf/exploit),
  // qui sinon n'incrémentaient aucun compteur côté client jusqu'à un refresh.
  loadReportCount();
  saveDashboardStats();
}

// ── PERSISTANCE DES STATS DU TABLEAU DE BORD ─────────────────────────────────
// Les compteurs/graphes/activité étaient en mémoire seule -> remis à zéro au
// refresh. On les recharge du serveur à la connexion et on enregistre un
// instantané (débouncé) à chaque évolution. Persistance PAR UTILISATEUR
// (cohérent avec l'isolation des rapports). Le nombre de rapports n'est pas
// stocké ici : il vient toujours de loadReportCount() (vérité disque serveur).
var _saveStatsTimer = null;
function saveDashboardStats() {
  if (!ST.token && !ST.user) return; // pas connecté
  if (_saveStatsTimer) clearTimeout(_saveStatsTimer);
  _saveStatsTimer = setTimeout(function() {
    var snap = {
      stats: { vulns: ST.stats.vulns||0, scans: ST.stats.scans||0, hosts: ST.stats.hosts||0 },
      vulnData: { crit: vulnData.crit||0, high: vulnData.high||0, med: vulnData.med||0, low: vulnData.low||0 },
      kpis: scanKPIs.slice(0, 20),
      activity: ST.activity.slice(0, 10)
    };
    apiFetch('/api/dashboard/stats', { method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(snap) }).catch(function(){});
  }, 400);
}

async function loadDashboardStats() {
  try {
    var res = await apiFetch('/api/dashboard/stats');
    var d = await res.json();
    if (d.stats) { ST.stats.vulns = d.stats.vulns||0; ST.stats.scans = d.stats.scans||0; ST.stats.hosts = d.stats.hosts||0; }
    if (Array.isArray(d.kpis)) {
      scanKPIs = d.kpis;
      if (scanKPIs.length) {
        renderKPITable();
        renderActivityChart(scanKPIs);
      }
    }
    if (Array.isArray(d.activity) && d.activity.length) {
      ST.activity = d.activity;
      var el = document.getElementById('recent-activity');
      if (el) el.innerHTML = ST.activity.map(function(a) {
        return '<div class="recent-item"><div class="ri-dot" style="background:'+a.color+'"></div><svg class="icon" style="width:14px;height:14px;color:'+a.color+'"><use href="#icon-'+a.icon+'"/></svg><div style="font-size:12px;font-family:var(--sans);font-weight:500;flex:1">'+escapeHtml(a.text)+'</div><div style="font-size:11px;color:var(--text3);font-family:var(--mono)">'+a.time+'</div></div>';
      }).join('');
    }
    if (d.vulnData) {
      var v = d.vulnData;
      if ((v.crit||0)+(v.high||0)+(v.med||0)+(v.low||0) > 0) updateVulnChart(v.crit||0, v.high||0, v.med||0, v.low||0);
    }
    // Rafraîchit les compteurs (sans re-déclencher une sauvegarde immédiate).
    countUpTo(document.getElementById('dash-vulns'), ST.stats.vulns, 600);
    countUpTo(document.getElementById('dash-scans'), ST.stats.scans, 600);
    countUpTo(document.getElementById('dash-hosts'), ST.stats.hosts, 600);
  } catch(e) { /* pas de stats encore — état vide, normal */ }
}

async function clearDashboardStats() {
  var ok = await uiConfirm('Effacer toutes vos statistiques du tableau de bord (compteurs, graphe d\'activité, vulnérabilités, activité récente) ? Les rapports déjà enregistrés ne sont pas affectés.',
    { title: 'Effacer les statistiques', danger: true, okText: 'Effacer' });
  if (!ok) return;
  try {
    await apiFetch('/api/dashboard/stats', { method: 'DELETE' });
  } catch(e) {}
  // Réinitialise l'état local + graphes.
  ST.stats.vulns = 0; ST.stats.scans = 0; ST.stats.hosts = 0;
  scanKPIs = [];
  ST.activity = [];
  vulnData = {crit:0, high:0, med:0, low:0};
  renderActivityChart([]);
  renderVulnChart(0, 0, 0, 0);
  var kt = document.getElementById('kpi-table');
  if (kt) kt.innerHTML = '<div style="color:var(--text3);font-family:var(--sans);font-size:12px">Aucun scan effectué pour l\'instant.</div>';
  var ra = document.getElementById('recent-activity');
  if (ra) ra.innerHTML = '<div class="recent-item"><div class="ri-dot" style="background:var(--text3)"></div><div style="color:var(--text3);font-family:var(--sans);font-size:12px">Aucune activité — lancez votre premier scan</div></div>';
  ['leg-crit','leg-high','leg-med','leg-low'].forEach(function(id){ var e=document.getElementById(id); if(e) e.textContent='0'; });
  countUpTo(document.getElementById('dash-vulns'), 0, 300);
  countUpTo(document.getElementById('dash-scans'), 0, 300);
  countUpTo(document.getElementById('dash-hosts'), 0, 300);
  uiAlert('Statistiques effacées.', { title: 'Tableau de bord' });
}

// ── SYS INFO ──────────────────────────────────────────────────────────────
async function loadSysInfo() {
  try {
    var res = await apiFetch('/api/status');
    var data = await res.json();
    document.getElementById('sys-info').textContent = data.os + ' | Python ' + data.python;
    ST.stats.reports = data.reports_count;
    updateDashboard();
  } catch(e) {
    document.getElementById('sys-info').textContent = 'Flask actif';
  }
}

// Source unique de vérité pour TOUS les compteurs de rapports : badge latéral,
// libellé de la page Rapports, carte du tableau de bord + ST.stats.reports.
// Appelé après chaque génération/suppression (manuelle OU auto via un scan).
function setReportCount(n) {
  n = n || 0;
  var badge = document.getElementById('reports-badge');
  if (badge) { badge.style.display = n > 0 ? 'inline-block' : 'none'; badge.textContent = n; }
  var label = document.getElementById('reports-count-label');
  if (label) label.textContent = n + ' rapport' + (n > 1 ? 's' : '');
  ST.stats.reports = n;
  var dash = document.getElementById('dash-reports');
  if (dash) countUpTo(dash, n, 400);
}
async function loadReportCount() {
  try {
    var res = await apiFetch('/api/status');
    var data = await res.json();
    setReportCount(data.reports_count);
  } catch(e) {}
}

// ── COMPTEUR DE SESSIONS (BUG 5) ─────────────────────────────────────────────
// Badge live "Sessions (N)" dans la barre latérale, comme le compteur de
// rapports. Mis à jour à l'ouverture/fermeture d'une session et par un sondage
// périodique léger (les sessions peuvent être ouvertes depuis la page
// Metasploit, sans passer par la page Sessions).
function setSessionCount(n) {
  n = n || 0;
  var badge = document.getElementById('sessions-badge');
  if (badge) { badge.style.display = n > 0 ? 'inline-block' : 'none'; badge.textContent = n; }
}
async function loadSessionCount() {
  try {
    var res = await apiFetch('/api/sessions');
    var data = await res.json();
    if (!data.error && Array.isArray(data.sessions)) setSessionCount(data.sessions.length);
  } catch(e) {}
}
var _sessionPollTimer = null;
function startSessionCountPolling() {
  loadSessionCount();
  if (_sessionPollTimer) clearInterval(_sessionPollTimer);
  _sessionPollTimer = setInterval(loadSessionCount, 25000);
}

var TOOL_LABELS = {
  'nmap': 'Nmap', 'dig': 'dig (DNS)', 'host': 'host (DNS)',
  'nslookup': 'nslookup (DNS)', 'curl': 'curl',
  'hydra': 'Hydra', 'nikto': 'Nikto', 'sqlmap': 'SQLMap',
  'enum4linux-ng': 'enum4linux-ng', 'gvm-cli': 'OpenVAS (gvm-cli)'
};

async function loadTools() {
  var container = document.getElementById('tools-content');
  // Le sondage des services (gvmd/msfrpcd) prend quelques secondes -> feedback.
  container.innerHTML = '<div class="alert alert-info"><svg class="icon" style="width:15px;height:15px"><use href="#icon-info"/></svg> Vérification de la chaîne d\'outils (sondage des services en cours)…</div>';
  var STATUS_META = {
    ok:          { color: 'var(--green)', icon: 'icon-check',          text: 'Disponible' },
    unreachable: { color: 'var(--orange)', icon: 'icon-alert-triangle', text: 'Injoignable' },
    absent:      { color: 'var(--red)',   icon: 'icon-x',              text: 'Absent' }
  };
  try {
    var res = await apiFetch('/api/tools/status');
    var data = await res.json();
    var sysCard = '<div class="card"><div class="card-title"><svg class="icon" style="width:15px;height:15px"><use href="#icon-monitor"/></svg> Système</div>' +
      '<div style="font-family:var(--mono);font-size:13px;line-height:2">' +
      '<div>OS: <span style="color:var(--accent)">' + data.os + '</span></div>' +
      '<div>Python: <span style="color:var(--accent)">' + data.python + '</span></div>' +
      '<div>Mode: <span style="color:var(--accent)">' + (data.docker ? 'Docker' : 'Standalone') + '</span></div></div></div>';
    var groupsHtml = (data.groups || []).map(function(g) {
      var items = g.tools.map(function(t) {
        var m = STATUS_META[t.status] || STATUS_META.absent;
        return '<div class="tool-status-item" style="flex-wrap:wrap" title="' + (t.detail || '') + '">' +
          '<svg class="icon" style="width:15px;height:15px;color:' + m.color + '"><use href="#' + m.icon + '"/></svg>' +
          '<span style="font-weight:600">' + t.label + '</span>' +
          '<span style="color:' + m.color + ';margin-left:auto">' + m.text + '</span>' +
          (t.detail ? '<span style="flex-basis:100%;font-size:11px;color:var(--text3);font-family:var(--mono);word-break:break-all">' + t.detail + '</span>' : '') +
          '</div>';
      }).join('');
      return '<div class="card"><div class="card-title"><svg class="icon" style="width:15px;height:15px"><use href="#icon-wrench"/></svg> ' + g.name + '</div><div class="tool-status-grid">' + items + '</div></div>';
    }).join('');
    container.innerHTML = sysCard + groupsHtml;
  } catch(e) {
    container.innerHTML = '<div class="alert alert-err"><svg class="icon" style="width:16px;height:16px"><use href="#icon-x"/></svg> Erreur: ' + e.message + '</div>';
  }
}

// ── DNS DUMPSTER ──────────────────────────────────────────────────────────
async function runDNSDumpster() {
  var dnsStart = Date.now();
  const domain = document.getElementById('dumpster-target').value.trim();
  if (!domain) return uiAlert('Entrez un domaine.');
  const btn = document.getElementById('dumpster-btn');
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  document.getElementById('dumpster-results-card').style.display = 'none';
  const stop = progressStart('dumpster-pb','dumpster-fill',8000);
  
  termSet('dumpster-out', `[*] DNSDumpster → ${domain}\n[*] Exécution en cours (dig / socket)...`);
  
  try {
    const res = await apiFetch('/api/dnsdumpster', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({domain})
    });
    const data = await res.json();
    
    if (data.error) {
      termSet('dumpster-out', `[!] ${data.error}`);
    } else {
      termSet('dumpster-out', data.log.join('\n'));
      renderDNSTable(data);
      ST.stats.hosts += data.a.length;
    }
    ST.stats.scans++;
    addActivity('globe', `DNSDumpster → ${domain} (${data.a?.length||0} sous-domaines)`, 'var(--accent)');
  } catch(e) {
    termSet('dumpster-out', `[!] Erreur: ${e.message}`);
  }
  
  stop(); btn.disabled=false; updateDashboard();
  stop(); btn.disabled=false; updateDashboard();
}

function renderDNSTable(data) {
  let html = '';
  if (data.a?.length) {
    html += `<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-server"/></svg> Enregistrements A — ${data.a.length} sous-domaine(s)</div>`;
    html += `<div class="dns-row" style="color:var(--text3);font-size:10px;letter-spacing:1px;text-transform:uppercase"><span>Hôte</span><span>IP</span><span>Info</span></div>`;
    html += data.a.map(r => `<div class="dns-row"><span style="color:var(--text)">${r.host}</span><span style="color:var(--yellow)">${r.ip}</span><span style="color:var(--text3)">—</span></div>`).join('');
  }
  if (data.mx?.length) {
    html += `<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-mail"/></svg> MX — ${data.mx.length} serveur(s) de messagerie</div>`;
    html += data.mx.map(r => `<div class="dns-row"><span style="color:var(--text)">${r.host}</span><span style="color:var(--yellow)">${r.ip}</span><span style="color:var(--text3)">Priorité: ${r.priority}</span></div>`).join('');
  }
  if (data.ns?.length) {
    html += `<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-hash"/></svg> NS — ${data.ns.length} nameserver(s)</div>`;
    html += data.ns.map(r => `<div class="dns-row"><span style="color:var(--text)">${r.host}</span><span style="color:var(--yellow)">${r.ip}</span><span></span></div>`).join('');
  }
  if (data.txt?.length) {
    html += `<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-file-text"/></svg> TXT — ${data.txt.length} enregistrement(s)</div>`;
    html += data.txt.map(r => `<div style="padding:7px 8px;font-family:var(--mono);font-size:11px;color:var(--text2);border-bottom:1px solid var(--bg3)">"${r}"</div>`).join('');
  }
  document.getElementById('dumpster-structured').innerHTML = html;
  document.getElementById('dumpster-results-card').style.display = 'block';
}

// ── RECON PASSIVE (dnsrecon) ───────────────────────────────────────────────
async function runRecon() {
  var t0 = Date.now();
  var domain = document.getElementById('recon-target').value.trim();
  if (!domain) return uiAlert('Entrez un nom de domaine.');
  // Validation côté client : un domaine, pas une IP (le serveur revalide).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return uiAlert('Entrez un nom de domaine (ex : exemple.com), pas une adresse IP.');
  var modes = [];
  if (document.getElementById('recon-std').checked) modes.push('std');
  if (document.getElementById('recon-crt').checked) modes.push('crt');
  if (document.getElementById('recon-axfr').checked) modes.push('axfr');
  if (!modes.length) return uiAlert('Sélectionnez au moins un module.');

  var btn = document.getElementById('recon-btn');
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  document.getElementById('recon-results-card').style.display = 'none';
  var stop = progressStart('recon-pb', 'recon-fill', 30000);
  termSet('recon-out', '[*] Reconnaissance passive → ' + domain + '\n[*] Modules : ' + modes.join(', ') + '\n[*] Interrogation crt.sh / DNS (peut prendre 10-60s)...');

  try {
    var res = await apiFetch('/api/recon', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({domain: domain, modes: modes}) });
    var data = await res.json();
    if (data.error) {
      termSet('recon-out', '[!] ' + data.error + (data.install ? '\nInstall : ' + data.install : ''));
    } else {
      termSet('recon-out', data.output);
      renderReconSections(data.sections);
      var nSub = (data.sections.subdomains || []).length;
      ST.stats.hosts += (data.sections.hosts || []).length;
      addScanKPI('RECON', domain, Math.round((Date.now()-t0)/1000), nSub, nSub === 1 ? 'sous-domaine' : 'sous-domaines');
      if (data.report_id) { notify('Rapport auto généré : ' + data.report_id, 'info'); loadReportCount(); }
    }
    ST.stats.scans++;
    addActivity('search', 'Recon passive → ' + domain, 'var(--green)');
    updateDashboard();
  } catch(e) {
    termSet('recon-out', '[!] Erreur : ' + e.message);
  }
  stop(); btn.disabled = false; document.getElementById('nmap-stop-btn').style.display = 'none';
}

function renderReconSections(s) {
  s = s || {};
  function host_rows(arr, extra) {
    return arr.map(function(r) {
      return '<div class="dns-row"><span style="color:var(--text)">' + escapeHtml(r.host || '') + '</span>' +
             '<span style="color:var(--yellow)">' + escapeHtml(r.ip || '') + '</span>' +
             '<span style="color:var(--text3)">' + (extra ? escapeHtml(extra(r)) : '—') + '</span></div>';
    }).join('');
  }
  var html = '';
  if ((s.subdomains || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-globe"/></svg> Sous-domaines (Certificate Transparency) — ' + s.subdomains.length + '</div>';
    html += '<div class="dns-row" style="color:var(--text3);font-size:10px;letter-spacing:1px;text-transform:uppercase"><span>Hôte</span><span>IP</span><span>Source</span></div>';
    html += host_rows(s.subdomains, function(){ return 'CT log'; });
  }
  if ((s.emails || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-mail"/></svg> Emails exposés — ' + s.emails.length + '</div>';
    html += s.emails.map(function(e){ return '<div style="padding:7px 8px;font-family:var(--mono);font-size:12px;color:var(--accent);border-bottom:1px solid var(--bg3)">' + escapeHtml(e) + '</div>'; }).join('');
  }
  if ((s.hosts || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-server"/></svg> Hôtes (A/AAAA) — ' + s.hosts.length + '</div>';
    html += host_rows(s.hosts);
  }
  if ((s.mail || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-mail"/></svg> MX — ' + s.mail.length + '</div>';
    html += host_rows(s.mail);
  }
  if ((s.nameservers || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-hash"/></svg> NS — ' + s.nameservers.length + '</div>';
    html += host_rows(s.nameservers);
  }
  if ((s.srv || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-hash"/></svg> SRV — ' + s.srv.length + '</div>';
    html += s.srv.map(function(r){ return '<div class="dns-row"><span style="color:var(--text)">' + escapeHtml(r.host||'') + '</span><span style="color:var(--text2)">' + escapeHtml(r.target||'') + '</span><span style="color:var(--text3)">port ' + escapeHtml(String(r.port||'')) + '</span></div>'; }).join('');
  }
  if ((s.txt || []).length) {
    html += '<div class="dns-section-header"><svg class="icon" style="width:13px;height:13px"><use href="#icon-file-text"/></svg> TXT — ' + s.txt.length + '</div>';
    html += s.txt.map(function(r){ return '<div style="padding:7px 8px;font-family:var(--mono);font-size:11px;color:var(--text2);border-bottom:1px solid var(--bg3);word-break:break-all">"' + escapeHtml(r) + '"</div>'; }).join('');
  }
  if (!html) html = '<div style="color:var(--text3);font-family:var(--sans);font-size:12px">Aucun résultat trouvé pour ce domaine.</div>';
  document.getElementById('recon-structured').innerHTML = html;
  document.getElementById('recon-results-card').style.display = 'block';
}

// ── DNS LOOKUP ─────────────────────────────────────────────────────────────
async function runDNS() {
  const target = document.getElementById('dns-target').value.trim();
  const type = document.getElementById('dns-type').value;
  if (!target) return uiAlert('Entrez un domaine.');
  termSet('dns-out', `[*] DNS ${type} → ${target}...`);
  try {
    const res = await apiFetch('/api/dns', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target, type})
    });
    const data = await res.json();
    termSet('dns-out', data.output || `[!] ${data.error}`);
    ST.stats.scans++; addActivity('search', `DNS ${type} → ${target}`, 'var(--accent)'); updateDashboard();
  } catch(e) { termSet('dns-out', `[!] ${e.message}`); }
}

// ── ÉNUMÉRATION SMB (enum4linux-ng) ─────────────────────────────────────────
async function runEnum4linux() {
  var target = document.getElementById('enum-target').value.trim();
  if (!target) return uiAlert('Entrez une cible (IP ou hôte).');
  var mode     = document.getElementById('enum-mode').value;
  var username = document.getElementById('enum-username').value.trim();
  var password = document.getElementById('enum-password').value;
  var btn = document.getElementById('enum-btn');
  btn.disabled = true;
  var stop = progressStart('enum-pb', 'enum-fill', 60000);
  termSet('enum-out', '[*] enum4linux-ng → ' + target + ' (' + mode + ')\n[*] En cours...');
  try {
    var res = await apiFetch('/api/enum4linux', {
      method: 'POST',
      body: JSON.stringify({ target: target, mode: mode, username: username, password: password })
    });
    var data = await res.json();
    if (data.error) {
      termSet('enum-out', '[!] ' + data.error + (data.install ? '\nInstall: ' + data.install : ''));
    } else {
      termSet('enum-out', data.output);
      if (data.elapsed) {
        var sd = scanDiscovery('SMB', data.output);
        addScanKPI('SMB', target, data.elapsed, sd.count, sd.label);
      }
      ST.stats.scans++;
      addActivity('server', 'Énum. SMB → ' + target, 'var(--accent)');
      updateDashboard();
    }
  } catch(e) { termSet('enum-out', '[!] ' + e.message); }
  stop(); btn.disabled = false;
}

// ── NMAP ──────────────────────────────────────────────────────────────────
// ── SUGGESTIONS D'EXPLOITATION ───────────────────────────────────────────────
// Navigue vers la page d'un outil et preremplit sa cible (depuis une suggestion).
function goToToolWithTarget(page, target) {
  if (!page) return;
  var navEl = document.querySelector('.nav-item[onclick*="showPage(\'' + page + '\'"]');
  showPage(page, navEl);
  var input = document.getElementById(page + '-target');
  if (input && target) input.value = target;
}

async function showExploitSuggestions(containerId, cardId, scanType, target, resultsText) {
  var card = document.getElementById(cardId);
  var container = document.getElementById(containerId);
  if (!card || !container) return;
  try {
    var res = await apiFetch('/api/exploit/suggest', { method:'POST', body: JSON.stringify({scan_type:scanType, results:resultsText}) });
    var data = await res.json();
    var suggestions = data.suggestions || [];
    if (!suggestions.length) { card.style.display = 'none'; return; }
    container.innerHTML = '';
    suggestions.forEach(function(s) {
      var item = document.createElement('div');
      item.className = 'suggestion-item';
      var info = document.createElement('div');
      info.className = 'suggestion-info';
      var h4 = document.createElement('h4'); h4.textContent = s.name;
      var p = document.createElement('p'); p.textContent = s.reason;
      info.appendChild(h4); info.appendChild(p);
      item.appendChild(info);
      if (s.page) {
        var btn = document.createElement('button');
        btn.className = 'suggestion-go';
        btn.innerHTML = '<svg class="icon" style="width:12px;height:12px"><use href="#icon-arrow-right"/></svg>';
        btn.prepend(document.createTextNode(s.name + ' '));
        btn.addEventListener('click', function() { goToToolWithTarget(s.page, target); });
        item.appendChild(btn);
      } else {
        var manual = document.createElement('span');
        manual.style.fontSize = '11px'; manual.style.color = 'var(--text3)'; manual.style.fontFamily = 'var(--mono)';
        manual.textContent = 'Manuel';
        item.appendChild(manual);
      }
      container.appendChild(item);
    });
    card.style.display = 'block';
  } catch(e) { card.style.display = 'none'; }
}

async function runNmap() {
  var target = document.getElementById('nmap-target').value.trim();
  document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  var type = document.getElementById('nmap-type').value;
  if (!target) return uiAlert('Entrez une cible.');
  var btn = document.getElementById('nmap-btn');
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  document.getElementById('nmap-suggestions-card').style.display = 'none';
  var stop = progressStart('nmap-pb','nmap-fill',60000);
  termSet('nmap-out', '[*] Nmap → ' + target + ' (type: ' + type + ')\n[*] En cours... (30-120s)');
  try {
    var res = await apiFetch('/api/nmap', { method:'POST', body: JSON.stringify({target:target, type:type}) });
    var data = await res.json();
    if (data.error) termSet('nmap-out', data.output || ('[!] ' + data.error));
    else {
      termSet('nmap-out', '[*] Commande: ' + data.command + '\n\n' + data.output);
      document.getElementById('exploit-target').value = target;
      ST.stats.hosts++;
      showExploitSuggestions('nmap-suggestions', 'nmap-suggestions-card', 'nmap', target, data.output);
    }
    if (data.elapsed) { var nd = scanDiscovery('NMAP', data.output); addScanKPI('NMAP', target, data.elapsed, nd.count, nd.label); }
    ST.stats.scans++; addActivity('search', 'Nmap → ' + target, 'var(--yellow)'); updateDashboard();
  } catch(e) { termSet('nmap-out', '[!] ' + e.message); }
  stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
  stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
}

// ── NIKTO ─────────────────────────────────────────────────────────────────
async function runNikto() {
  var target = document.getElementById('nikto-target').value.trim();
  document.getElementById('nikto-stop-btn').style.display = 'inline-block';
  if (!target) return uiAlert('Entrez une cible.');
  var btn = document.getElementById('nikto-btn'); document.getElementById('nikto-stop-btn').style.display = 'inline-block';
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  document.getElementById('nikto-suggestions-card').style.display = 'none';
  var stop = progressStart('nikto-pb','nikto-fill',180000);
  var extraHost = document.getElementById('nikto-host') ? document.getElementById('nikto-host').value.trim() : '';
  termSet('nikto-out', '[*] Nikto → ' + target + '\n[*] En cours... (2-5 minutes)');
  try {
    var res = await apiFetch('/api/nikto', { method:'POST', body: JSON.stringify({target:target, extra_host:extraHost}) });
    var data = await res.json();
    termSet('nikto-out', data.error ? '[!] ' + data.error + '\nInstall: ' + (data.install||'') : data.output);
    if (!data.error) showExploitSuggestions('nikto-suggestions', 'nikto-suggestions-card', 'nikto', target, data.output);
    ST.stats.scans++; addActivity('globe', 'Nikto → ' + target, 'var(--orange)'); updateDashboard();
  } catch(e) { termSet('nikto-out', '[!] ' + e.message); }
  stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
  document.getElementById('nikto-stop-btn').style.display = 'none';
  stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
}

// ── OPENVAS ───────────────────────────────────────────────────────────────
// Les UUID des port lists sont résolus à chaud côté serveur (cf. app.py
// /api/openvas/port_lists qui interroge gvmd via <get_port_lists/>) : on ne
// code donc aucun UUID ici, le <select> est peuplé dynamiquement. La dernière
// option « Custom… » bascule sur un champ de saisie de plage libre.
var OPENVAS_CUSTOM_VAL = '__custom__';
async function loadOpenVASPortLists() {
  var sel = document.getElementById('openvas-portlist');
  if (!sel) return;
  try {
    var res = await apiFetch('/api/openvas/port_lists');
    var data = await res.json();
    if (!res.ok || data.error) { sel.innerHTML = '<option value="">Indisponible</option>'; return; }
    var opts = (data.port_lists || []).map(function(pl) {
      var selAttr = (pl.id === data.default_id) ? ' selected' : '';
      return '<option value="' + pl.id + '"' + selAttr + '>' + pl.name + ' (' + pl.count + ' ports)</option>';
    });
    opts.push('<option value="' + OPENVAS_CUSTOM_VAL + '">Custom (plage manuelle)…</option>');
    sel.innerHTML = opts.join('');
    onOpenVASPortlistChange();
  } catch(e) { /* page OpenVAS pas encore visible / API indisponible — pas bloquant */ }
}

function onOpenVASPortlistChange() {
  var sel = document.getElementById('openvas-portlist');
  var field = document.getElementById('openvas-custom-field');
  if (!sel || !field) return;
  field.style.display = (sel.value === OPENVAS_CUSTOM_VAL) ? '' : 'none';
}

function _openvasStopBtn(show) {
  var b = document.getElementById('openvas-stop-btn');
  if (b) b.style.display = show ? 'inline-block' : 'none';
}
async function runOpenVAS() {
  var target = document.getElementById('openvas-target').value.trim();
  if (!target) return uiAlert('Entrez une cible.');
  var sel = document.getElementById('openvas-portlist');
  var portChoice = sel ? sel.value : '';
  var body = { target: target };
  if (portChoice === OPENVAS_CUSTOM_VAL) {
    var custom = (document.getElementById('openvas-custom-ports').value || '').trim();
    if (!custom) return uiAlert('Entrez une plage de ports custom (ex: T:1-1000).');
    body.custom_ports = custom;
  } else if (portChoice) {
    body.port_list_id = portChoice;
  }
  var btn = document.getElementById('openvas-btn');
  btn.disabled = true;
  document.getElementById('openvas-results-card').style.display = 'none';
  _openvasStopBtn(true);
  termSet('openvas-out', '[*] OpenVAS → ' + target + '\n[*] Démarrage du scan GVM...');

  try {
    var res = await apiFetch('/api/scan/openvas', { method:'POST', body: JSON.stringify(body) });
    var data = await res.json();
    if (!res.ok || data.error) {
      _openvasStopBtn(false);
      termSet('openvas-out', '[!] ' + (data.error || 'Erreur inconnue') + (data.install ? '\nInstall: ' + data.install : ''));
      btn.disabled = false;
      return;
    }
    ST.openvasJobId = data.job_id;  // mémorisé pour stopScan('openvas') -> GMP stop_task
    termSet('openvas-out', '[*] Job ' + data.job_id + ' démarré (ports: ' + (data.port_list || 'défaut') + ') → suivi toutes les 15s...');
    pollOpenVAS(data.job_id, target, btn);
  } catch(e) {
    _openvasStopBtn(false);
    termSet('openvas-out', '[!] ' + e.message);
    btn.disabled = false;
  }
}

// Le scan dure trop longtemps pour bloquer la requête HTTP côté Flask
// (cf. /api/scan/openvas qui renvoie un job_id) : on poll donc côté client,
// toutes les 15s, jusqu'à recevoir un statut "done" ou "error".
// ETA lisible à partir de secondes (ex: 4m12s, 1h05m). Utilisé par le suivi
// enrichi OpenVAS ; l'ETA lui-même est une estimation linéaire côté serveur.
function fmtDuration(s) {
  s = Math.max(0, Math.round(s));
  var m = Math.floor(s / 60), sec = s % 60;
  if (m >= 60) { var h = Math.floor(m / 60); return h + 'h' + String(m % 60).padStart(2, '0') + 'm'; }
  return m + 'm' + String(sec).padStart(2, '0') + 's';
}

function pollOpenVAS(jobId, target, btn) {
  var statusBox = document.getElementById('openvas-status');
  var statusText = document.getElementById('openvas-status-text');
  statusBox.style.display = 'block';

  var iv = setInterval(async function() {
    try {
      var res = await apiFetch('/api/scan/openvas/' + jobId);
      var data = await res.json();

      if (!res.ok || data.error) {
        clearInterval(iv);
        statusBox.style.display = 'none';
        _openvasStopBtn(false);
        termSet('openvas-out', '[!] ' + (data.error || 'job_id inconnu'));
        btn.disabled = false; ST.openvasJobId = null;
        return;
      }

      if (data.status === 'done') {
        clearInterval(iv);
        statusBox.style.display = 'none';
        _openvasStopBtn(false);
        var findings = data.findings || [];
        termSet('openvas-out', '[+] Scan terminé → ' + target + '\n[+] ' + findings.length + ' résultat(s) remonté(s)');
        renderOpenVASTable(findings);
        ST.stats.vulns += findings.length;
        ST.stats.scans++;
        addActivity('shield-alert', 'OpenVAS → ' + target + ' — ' + findings.length + ' résultat(s)', 'var(--red)');
        updateDashboard();
        btn.disabled = false; ST.openvasJobId = null;
        return;
      }

      if (data.status === 'stopped') {
        clearInterval(iv);
        statusBox.style.display = 'none';
        _openvasStopBtn(false);
        termSet('openvas-out', '[■] Scan arrêté par l\'utilisateur → ' + target);
        btn.disabled = false; ST.openvasJobId = null;
        return;
      }

      if (data.status === 'error') {
        clearInterval(iv);
        statusBox.style.display = 'none';
        _openvasStopBtn(false);
        termSet('openvas-out', '[!] ' + (data.error || 'Le scan a échoué'));
        btn.disabled = false; ST.openvasJobId = null;
        return;
      }

      // "starting" / "running" → on continue de poller. On affiche le suivi
      // enrichi renvoyé par le worker (cf. _openvas_progress_snapshot) dans le
      // même terminal, sans changer l'archi de poll : phase, hôte/NVT courant,
      // comptes de résultats live + sévérité, ETA estimé.
      var pct = (typeof data.progress === 'number' && data.progress >= 0) ? data.progress + '%' : '…';
      statusText.textContent = 'Scan en cours (' + pct + ')... (cela peut prendre du temps)';
      var phase = data.phase || (data.status === 'starting' ? 'Initialisation' : 'Running');
      var lines = ['[*] OpenVAS → ' + target,
                   '[~] Phase: ' + phase + ' — ' + pct +
                     (data.eta_seconds ? '  (reste ~' + fmtDuration(data.eta_seconds) + ')' : '')];
      if (data.current) {
        lines.push('[~] En cours: ' + data.current.host + ' ' + data.current.port +
                   ' — ' + (data.current.nvt || '?'));
      }
      if (typeof data.results_total === 'number') {
        var sc = data.sev_counts || {};
        lines.push('[~] Résultats live: ' + data.results_total +
                   ' (vulns: ' + (data.vuln_count || 0) + ')' +
                   (data.highest_sev ? ' — sévérité max: ' + data.highest_sev : ''));
        lines.push('[~] Sévérités → High:' + (sc.high || 0) + ' Medium:' + (sc.medium || 0) +
                   ' Low:' + (sc.low || 0) + ' Log:' + (sc.log || 0));
      } else {
        lines.push('[~] En attente des premiers résultats…');
      }
      _openvasStopBtn(true); termSet('openvas-out', lines.join('\n'));
    } catch(e) {
      // Échec réseau ponctuel pendant le poll : on retente au prochain tick
      // plutôt que d'abandonner le suivi pour un seul aléa transitoire.
    }
  }, 15000);
}

function renderOpenVASTable(findings) {
  if (!findings.length) {
    document.getElementById('openvas-table').innerHTML = '<div class="alert alert-info"><svg class="icon" style="width:14px;height:14px"><use href="#icon-info"/></svg> Aucune vulnérabilité détectée par OpenVAS.</div>';
    document.getElementById('openvas-results-card').style.display = 'block';
    return;
  }
  // Même ordre de sévérité et mêmes classes CSS vuln-badge que renderVulnTable(),
  // pour rester cohérent avec _map_severity() côté app.py (critical/high/medium/low).
  var order = {critical:0, high:1, medium:2, low:3};
  findings.sort(function(a,b){ return (order[a.severity]||9) - (order[b.severity]||9); });
  var rows = findings.map(function(v) {
    return '<tr><td><span class="vuln-badge vuln-' + v.severity + '">' + v.severity + '</span></td><td>' + v.name + '</td><td>' + (v.port||'-') + '</td><td style="color:var(--text3)">' + (v.cve||'-') + '</td><td style="font-size:11px;color:var(--text2)">' + (v.recommendation||'') + '</td></tr>';
  }).join('');
  document.getElementById('openvas-table').innerHTML = '<table class="result-table"><thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Port</th><th>CVE</th><th>Recommandation</th></tr></thead><tbody>' + rows + '</tbody></table>';
  document.getElementById('openvas-results-card').style.display = 'block';
}

// ── METASPLOIT ───────────────────────────────────────────────────────────
// /api/msf/modules est la même whitelist que celle vérifiée côté serveur dans
// /api/scan/msf (cf. app.py::MSF_ALLOWED_MODULES) — le <select> ne peut donc
// jamais proposer un module que la route refuserait de toute façon.
var MSF_MODULES = {};  // cache id -> {label, options, category, available, is_exploit, rpc_down}
var MSF_CAT_LABELS = { version: 'Détection de version', detection: 'Détection de CVE', exploit: 'Exploits', autre: 'Autres' };

async function loadMsfModules() {
  var sel = document.getElementById('msf-module');
  if (!sel) return;
  try {
    var res = await apiFetch('/api/msf/modules');
    MSF_MODULES = await res.json();
    var ids = Object.keys(MSF_MODULES);
    var rpcDown = ids.length && MSF_MODULES[ids[0]].rpc_down;
    // Regroupement par catégorie via <optgroup>, modules absents grisés/désactivés.
    var byCat = {};
    ids.forEach(function(id) {
      var c = MSF_MODULES[id].category || 'autre';
      (byCat[c] = byCat[c] || []).push(id);
    });
    sel.innerHTML = ['version', 'detection', 'exploit', 'autre'].filter(function(c) { return byCat[c]; }).map(function(c) {
      var opts = byCat[c].map(function(id) {
        var m = MSF_MODULES[id];
        var unavail = !m.available;
        return '<option value="' + id + '"' + (unavail ? ' disabled' : '') + '>' +
          m.label + (unavail ? (rpcDown ? ' — RPC injoignable' : ' — module absent') : '') + '</option>';
      }).join('');
      return '<optgroup label="' + (MSF_CAT_LABELS[c] || c) + '">' + opts + '</optgroup>';
    }).join('');
    onMsfModuleChange();
  } catch(e) { /* page Metasploit pas encore visible / API indisponible — pas bloquant */ }
}

// Affiche un champ de saisie par option du module (hors RHOSTS, auto-rempli par
// la cible). Permet de renseigner LHOST/LPORT/RPORT/TARGETURI requis par les
// exploits à payload reverse — auparavant impossible depuis l'UI.
function onMsfModuleChange() {
  var sel = document.getElementById('msf-module');
  var box = document.getElementById('msf-options');
  if (!sel || !box) return;
  var m = MSF_MODULES[sel.value];
  if (!m) { box.innerHTML = ''; return; }
  var ph = { LHOST: 'IP de retour (ex: votre IP)', LPORT: '4444', RPORT: 'port', TARGETURI: '/', PORTS: '1-1000', THREADS: '4' };
  box.innerHTML = (m.options || []).filter(function(o) { return o !== 'RHOSTS'; }).map(function(o) {
    return '<div class="field" style="max-width:170px"><label>' + o + '</label>' +
      '<input type="text" class="msf-opt" data-opt="' + o + '" placeholder="' + (ph[o] || '') + '"/></div>';
  }).join('');
}

async function runMSF() {
  var target = document.getElementById('msf-target').value.trim();
  var module = document.getElementById('msf-module').value;
  if (!target) return uiAlert('Entrez une cible.');
  var btn = document.getElementById('msf-btn');
  // Collecte des options saisies (LHOST/LPORT/RPORT/TARGETURI…) non vides.
  var options = {};
  document.querySelectorAll('#msf-options .msf-opt').forEach(function(inp) {
    if (inp.value.trim()) options[inp.dataset.opt] = inp.value.trim();
  });
  btn.disabled = true;
  termSet('msf-out', '[*] Metasploit → ' + target + '\n[*] Module: ' + module + '\n[*] Démarrage...');

  try {
    var res = await apiFetch('/api/scan/msf', { method:'POST', body: JSON.stringify({target:target, module:module, options:options}) });
    var data = await res.json();
    if (!res.ok || data.error) {
      termSet('msf-out', '[!] ' + (data.error || 'Erreur inconnue'));
      btn.disabled = false;
      return;
    }
    termSet('msf-out', '[*] Job ' + data.job_id + ' démarré → suivi toutes les 3s...');
    pollMSF(data.job_id, target, btn);
  } catch(e) {
    termSet('msf-out', '[!] ' + e.message);
    btn.disabled = false;
  }
}

// Contrairement à OpenVAS/GVM (poll 15s, scan de plusieurs minutes/heures),
// un module auxiliary/scanner se termine en quelques secondes — un poll
// toutes les 3s reste léger tout en donnant un retour quasi immédiat.
function pollMSF(jobId, target, btn) {
  var statusBox = document.getElementById('msf-status');
  statusBox.style.display = 'block';

  var iv = setInterval(async function() {
    try {
      var res = await apiFetch('/api/scan/msf/' + jobId);
      var data = await res.json();

      if (!res.ok || data.error) {
        clearInterval(iv);
        statusBox.style.display = 'none';
        termSet('msf-out', '[!] ' + (data.error || 'job_id inconnu'));
        btn.disabled = false;
        return;
      }

      if (data.status === 'done') {
        clearInterval(iv);
        statusBox.style.display = 'none';
        termSet('msf-out', data.output || '[+] Scan terminé, aucune sortie.');
        ST.stats.scans++;
        // Une session ouverte par cet exploit -> bannière + rafraîchissement
        // immédiat du compteur de sessions (sans attendre le sondage 25s).
        var opened = data.sessions_opened || [];
        if (opened.length) {
          notify('Session ouverte : #' + opened.map(function(s){return s.sid;}).join(', #') + ' sur ' + target, 'success');
          loadSessionCount();
        }
        addActivity('crosshair', 'Metasploit → ' + target + (opened.length ? ' — session #' + opened[0].sid : ''), opened.length ? 'var(--green)' : 'var(--accent)');
        updateDashboard();
        btn.disabled = false;
        return;
      }

      if (data.status === 'error') {
        clearInterval(iv);
        statusBox.style.display = 'none';
        termSet('msf-out', '[!] ' + (data.error || 'Le scan a échoué'));
        btn.disabled = false;
        return;
      }
      // "starting" / "running" → on continue de poller
    } catch(e) {
      // Échec réseau ponctuel pendant le poll : on retente au prochain tick.
    }
  }, 3000);
}

// ── SQLMAP ────────────────────────────────────────────────────────────────
async function loadSqlmapTampers() {
  var sel = document.getElementById('sqlmap-tamper');
  if (!sel) return;
  try {
    var res = await apiFetch('/api/sqlmap/tampers');
    var data = await res.json();
    sel.innerHTML = '<option value="">(aucun)</option>' +
      (data.tampers || []).map(function(t) { return '<option value="' + t + '">' + t + '</option>'; }).join('');
  } catch(e) { /* non bloquant */ }
  // Avertissement --dump (action intrusive d'exfiltration).
  var dump = document.getElementById('sqlmap-dump');
  if (dump) dump.addEventListener('change', function() {
    document.getElementById('sqlmap-dump-warn').style.display = dump.checked ? 'block' : 'none';
  });
}

async function runSQLMap() {
  var target = document.getElementById('sqlmap-target').value.trim();
  if (!target) return uiAlert('Entrez une URL.');
  var tamperVal = document.getElementById('sqlmap-tamper').value;
  var body = {
    target: target,
    technique: document.getElementById('sqlmap-technique').value,
    level: parseInt(document.getElementById('sqlmap-level').value, 10) || 1,
    risk: parseInt(document.getElementById('sqlmap-risk').value, 10) || 1,
    crawl: parseInt(document.getElementById('sqlmap-crawl').value, 10) || 0,
    toggles: {
      forms:  document.getElementById('sqlmap-forms').checked,
      dbs:    document.getElementById('sqlmap-dbs').checked,
      tables: document.getElementById('sqlmap-tables').checked,
      dump:   document.getElementById('sqlmap-dump').checked
    },
    tamper: tamperVal ? [tamperVal] : []
  };
  var btn = document.getElementById('sqlmap-btn');
  btn.disabled = true;
  document.getElementById('sqlmap-stop-btn').style.display = 'inline-block';
  var stop = progressStart('sqlmap-pb', 'sqlmap-fill', 60000);
  termSet('sqlmap-out', '[*] SQLMap → ' + target + '\n[*] En cours...');
  try {
    var res = await apiFetch('/api/sqlmap', { method:'POST', body: JSON.stringify(body) });
    var data = await res.json();
    termSet('sqlmap-out', data.error ? '[!] ' + data.error + '\nInstall: ' + (data.install||'') : data.output);
    ST.stats.scans++; addActivity('database', 'SQLMap → ' + target, 'var(--red)'); updateDashboard();
  } catch(e) { termSet('sqlmap-out', '[!] ' + e.message); }
  if (stop) stop();
  document.getElementById('sqlmap-stop-btn').style.display = 'none';
  btn.disabled = false;
}

// ── EXPLOITATION ──────────────────────────────────────────────────────────
// Lance de vrais scans nmap NSE côté serveur (/api/exploit/run) pour chaque
// service coché, puis affiche le log réel et les vulnérabilités structurées
// renvoyées. Remplace l'ancien simulateur Math.random() — les findings sont
// désormais réels avant d'alimenter le tableau, les graphes et le rapport.
async function runExploit() {
  var target = document.getElementById('exploit-target').value.trim();
  document.getElementById('exploit-stop-btn').style.display = 'inline-block';
  if (!target) return uiAlert('Entrez une cible.');
  var modules = [];
  document.querySelectorAll('#exploit-modules .checkbox-item.checked').forEach(function(l) {
    modules.push(l.querySelector('input').value);
  });
  if (!modules.length) return uiAlert('Sélectionnez au moins un module.');

  document.getElementById('exploit-results-card').style.display='none';
  document.getElementById('gen-report-btn').style.display='none';
  var btn = document.getElementById('exploit-btn');
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  var stop = progressStart('exploit-pb','exploit-fill', modules.length*60000);
  var termId = 'exploit-out';
  termSet(termId, '[*] Exploitation → ' + target + '\n[*] Modules: ' + modules.join(', ') +
    '\n[*] Scan nmap NSE en cours… (jusqu\'à ~3 min par module)');

  var vulnFound = [];
  try {
    var res = await apiFetch('/api/exploit/run', { method:'POST', body: JSON.stringify({target:target, modules:modules}) });
    var data = await res.json();
    if (!res.ok || data.error) {
      termSet(termId, '[!] ' + (data.error || 'Erreur inconnue'));
      stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
      stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
      return;
    }
    // Affiche le log serveur réel via le classifieur central (BUG 4) : même
    // coloration + bannière de succès que les autres outils.
    termSet(termId, data.output || '');
    vulnFound = data.vulnerabilities || [];
  } catch(e) {
    termSet(termId, '[!] ' + e.message);
    stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
    stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
    return;
  }
  stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';
  document.getElementById('nmap-stop-btn').style.display = 'none';
  stop(); btn.disabled=false; document.getElementById('nmap-stop-btn').style.display = 'none';

  if (vulnFound.length) {
    renderVulnTable(vulnFound, target);
    ST.stats.vulns += vulnFound.length;
    var c=0,h=0,m=0,l=0;
    vulnFound.forEach(function(v){if(v.severity==='critical')c++;else if(v.severity==='high')h++;else if(v.severity==='medium')m++;else l++;});
    updateVulnChart(c,h,m,l);
    document.getElementById('gen-report-btn').style.display='inline-block';
    addActivity('zap', 'Exploit → ' + target + ' — ' + vulnFound.length + ' vuln(s)', 'var(--red)');
  } else {
    addActivity('zap', 'Exploit → ' + target + ' — RAS', 'var(--green)');
    document.getElementById('gen-report-btn').style.display='none';
  }
  ST.lastExploit = { target:target, vulns:vulnFound, modules:modules };
  ST.stats.scans++; updateDashboard();
}

function renderVulnTable(vulns, target) {
  var order={critical:0,high:1,medium:2,low:3};
  vulns.sort(function(a,b){return order[a.severity]-order[b.severity];});
  document.getElementById('exploit-results-table').innerHTML='<table class="result-table"><thead><tr><th>#</th><th>Sévérité</th><th>Vulnérabilité</th><th>Service</th><th>CVE</th><th>Recommandation</th></tr></thead><tbody>'+vulns.map(function(v,i){return '<tr><td>#'+(i+1)+'</td><td><span class="vuln-badge vuln-'+v.severity+'">'+v.severity+'</span></td><td>'+v.name+'</td><td>'+v.module+'/Port '+v.port+'</td><td style=\'color:var(--text3)\'>'+(v.cve||'N/A')+'</td><td style=\'font-size:11px;color:var(--text2)\'>'+(v.recommendation||'')+'</td></tr>';}).join('')+'</tbody></table>';
  document.getElementById('exploit-results-card').style.display='block';
}

// ── REPORTS ───────────────────────────────────────────────────────────────
function openGenReport() {
  if (!ST.lastExploit) return;
  document.getElementById('modal-content').innerHTML='<h2 style="font-size:20px;font-weight:800;margin-bottom:20px;display:flex;align-items:center;gap:8px"><svg class="icon" style="width:18px;height:18px"><use href="#icon-file-text"/></svg> Générer un rapport</h2><div style="font-family:var(--mono);font-size:13px;color:var(--text2);margin-bottom:20px">Cible: <strong style=\'color:var(--accent)\'>' + ST.lastExploit.target + '</strong><br>Vulnérabilités: <strong style=\'color:var(--red)\'>' + ST.lastExploit.vulns.length + '</strong></div><button class="btn btn-success" onclick="generateReport()" style="width:100%"><svg class="icon" style="width:14px;height:14px"><use href="#icon-check"/></svg> Générer et sauvegarder</button>';
  document.getElementById('report-modal').classList.add('open');
}

async function generateReport() {
  if (!ST.lastExploit) return;
  closeModal();
  try {
    // Les modules du rapport = ceux REELLEMENT lances lors du scan (memorises dans
    // ST.lastExploit.modules par runExploit), et non l'etat courant des cases a
    // cocher: si l'utilisateur (dé)coche une case apres le scan, le rapport doit
    // refleter le scan effectue, pas la selection actuelle. Fallback sur l'etat
    // des cases pour les anciens scans sans cette info.
    var modules = ST.lastExploit.modules;
    if (!modules || !modules.length) {
      modules = [];
      document.querySelectorAll('#exploit-modules .checkbox-item.checked').forEach(function(l){ modules.push(l.querySelector('input').value); });
    }
    var res = await apiFetch('/api/report/generate', { method:'POST', body: JSON.stringify({ target:ST.lastExploit.target, vulnerabilities:ST.lastExploit.vulns, modules_run:modules }) });
    var data = await res.json();
    if (data.ok) {
      ST.stats.reports++;
      addActivity('file-text', 'Rapport '+data.report_id+' généré', 'var(--green)');
      updateDashboard(); loadReportCount();
      showPage('reports', null); loadReports();
      uiAlert('✓ Rapport ' + data.report_id + ' sauvegardé !');
    } else {
      // Ne pas echouer en silence: remonter l'erreur backend a l'operateur.
      uiAlert('✗ Échec de génération du rapport : ' + (data.error || ('HTTP ' + res.status)));
    }
  } catch(e) { uiAlert('Erreur: '+e.message); }
}

// ── RAPPORTS AUTOMATIQUES — toggles par outil (Improvement 3) ────────────────
var AUTOREPORT_LABELS = {nmap:'Nmap', enum4linux:'Énum. SMB', recon:'Recon passive',
  dnsdumpster:'DNSDumpster', metasploit:'Metasploit', exploit_auto:'Exploitation auto',
  sqlmap:'SQLMap', hydra:'Hydra', nikto:'Nikto', john:'John (cracking)', openvas:'OpenVAS'};
function toggleAutoReportPanel(titleEl) {
  var p = document.getElementById('autoreport-panel');
  var open = p.style.display === 'none' || !p.style.display;
  p.style.display = open ? 'block' : 'none';
  var chev = titleEl.querySelector('.ar-chev');
  if (chev) chev.textContent = open ? '▾' : '▸';
  if (open) loadAutoReportPrefs();
}
async function loadAutoReportPrefs() {
  var box = document.getElementById('autoreport-toggles');
  if (!box) return;
  try {
    var res = await apiFetch('/api/settings/auto-report');
    var data = await res.json();
    var prefs = data.auto_report || {};
    box.innerHTML = (data.tools || []).map(function(t) {
      return '<label class="check-inline"><input type="checkbox" data-tool="' + t + '"' + (prefs[t] !== false ? ' checked' : '') +
             ' onchange="saveAutoReportPref(this)"> ' + (AUTOREPORT_LABELS[t] || t) + '</label>';
    }).join('');
  } catch(e) { box.innerHTML = '<span style="color:var(--text3);font-size:12px">Indisponible.</span>'; }
}
async function saveAutoReportPref(input) {
  var body = {auto_report: {}};
  body.auto_report[input.getAttribute('data-tool')] = input.checked;
  try {
    await apiFetch('/api/settings/auto-report', {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    notify('Rapport auto ' + (input.checked ? 'activé' : 'désactivé') + ' : ' + (AUTOREPORT_LABELS[input.getAttribute('data-tool')] || ''), 'info');
  } catch(e) { uiAlert('Échec de l\'enregistrement.', {title:'Erreur', danger:true}); }
}

async function loadReports() {
  var container = document.getElementById('reports-container');
  try {
    var res = await apiFetch('/api/reports');
    var reports = await res.json();
    setReportCount(reports.length);  // compteur live depuis la liste réelle (pas un cache)
    if (!reports.length) { container.innerHTML='<div class="alert alert-info"><svg class="icon" style="width:14px;height:14px"><use href="#icon-info"/></svg> Aucun rapport — lancez une exploitation pour créer votre premier rapport.</div>'; return; }
    container.innerHTML = reports.map(function(r) {
      var modules = (r.modules_run||[]).join(', ') || 'Manuel';
      var autoBadge = r.auto ? ' <span class="vuln-badge" style="background:rgba(0,180,255,.15);color:#0bf">auto</span>' : '';
      return '<div class="report-item"><div class="report-icon"><svg class="icon" style="width:18px;height:18px"><use href="#icon-file-text"/></svg></div><div class="report-info"><h4>'+r.id+' — '+r.target+'</h4><p style="margin-bottom:4px"><span style="font-family:var(--mono);font-size:11px;color:var(--text2);display:inline-flex;align-items:center;gap:4px"><svg class="icon" style="width:11px;height:11px"><use href="#icon-sliders"/></svg> '+modules+'</span>'+autoBadge+'</p><p><span class="vuln-badge vuln-critical">'+(r.stats&&r.stats.critical||0)+' CRIT</span> <span class="vuln-badge vuln-high">'+(r.stats&&r.stats.high||0)+' HIGH</span> <span class="vuln-badge vuln-medium">'+(r.stats&&r.stats.medium||0)+' MED</span> <span class="vuln-badge vuln-low">'+(r.stats&&r.stats.low||0)+' LOW</span></p></div><div class="report-meta"><div>'+r.date_display+'</div><div>Expire '+r.expiry+'</div><div style="margin-top:4px;font-size:10px;color:var(--text3)">Par '+r.operator+'</div></div><div style="display:flex;flex-direction:column;gap:4px;min-width:90px"><a class="dl-btn dl-html" href="/api/report/'+r.id+'/html" target="_blank"><svg class="icon" style="width:12px;height:12px"><use href="#icon-eye"/></svg> HTML</a><a class="dl-btn dl-json" href="/api/report/'+r.id+'/json" download><svg class="icon" style="width:12px;height:12px"><use href="#icon-download"/></svg> JSON</a><a class="dl-btn dl-csv" href="/api/report/'+r.id+'/csv" download><svg class="icon" style="width:12px;height:12px"><use href="#icon-download"/></svg> CSV</a><button class="dl-btn" style="border-color:rgba(255,68,68,.3);color:var(--red);background:rgba(255,68,68,.08)" onclick="deleteReport(this.dataset.id)" data-id="'+r.id+'"><svg class="icon" style="width:12px;height:12px"><use href="#icon-trash"/></svg></button></div></div>';
    }).join('');
  } catch(e) { container.innerHTML='<div class="alert alert-err"><svg class="icon" style="width:14px;height:14px"><use href="#icon-x"/></svg> Erreur: '+e.message+'</div>'; }
}

async function deleteReport(id) {
  if (!(await uiConfirm('Supprimer le rapport ' + id + ' ?', {title:'Supprimer le rapport', okText:'Supprimer'}))) return;
  var res = await apiFetch('/api/report/'+id, {method:'DELETE'});
  try { var d = await res.json(); if (typeof d.reports_count === 'number') setReportCount(d.reports_count); } catch(e) {}
  loadReports();
}

async function deleteAllReports() {
  if (!(await uiConfirm('Supprimer TOUS les rapports ? Cette action est irréversible.', {title:'Tout supprimer', okText:'Tout supprimer'}))) return;
  try {
    var res = await apiFetch('/api/reports', {method:'DELETE'});
    var d = await res.json();
    if (d.ok) {
      setReportCount(d.reports_count || 0);
      loadReports();
      uiAlert(d.deleted + ' rapport(s) supprimé(s).', {title:'Rapports supprimés'});
    } else {
      uiAlert(d.error || 'Échec de la suppression.', {title:'Erreur', danger:true});
    }
  } catch(e) { uiAlert(e.message, {title:'Erreur réseau', danger:true}); }
}



// ── RBAC ─────────────────────────────────────────────────────────────────────
function applyRBAC(role) {
  // Pages réservées à l'admin : gestion des utilisateurs, journal d'audit,
  // paramètres système. Pour un analyste, on RETIRE complètement ces entrées de
  // la barre latérale (display:none) au lieu de simplement les griser — le
  // 403 serveur (require_admin) reste le vrai garde-fou, mais l'UI ne doit même
  // pas suggérer l'existence de ces pages (cf. BUG 6).
  var adminOnly = ['users', 'audit', 'settings'];
  var isAdmin = (role === 'admin');
  adminOnly.forEach(function(page) {
    var navItem = document.querySelector('[onclick*="showPage(\'' + page + '\'"]');
    if (navItem) navItem.style.display = isAdmin ? '' : 'none';
  });
  // Si un analyste se trouvait sur une page admin (improbable), on le ramène au
  // tableau de bord.
  if (!isAdmin) {
    adminOnly.forEach(function(page) {
      var pg = document.getElementById('page-' + page);
      if (pg && pg.classList.contains('active')) showPage('dashboard');
    });
  }
}

// ── GESTION UTILISATEURS ─────────────────────────────────────────────────────
async function loadUsers() {
  var container = document.getElementById('users-list');
  try {
    var res = await apiFetch('/api/users');
    if (res.status === 403) {
      container.innerHTML = '<div class="alert alert-warn">Acces reserve a l admin.</div>';
      return;
    }
    var data = await res.json();
    var users = data.users || [];

    if (!users.length) {
      container.innerHTML = '<div class="alert alert-info">Aucun utilisateur.</div>';
      return;
    }

    var html = '';
    for (var i = 0; i < users.length; i++) {
      var u = users[i];
      // Extrait username et role peu importe le format
      var username = '';
      var role = 'analyst';
      if (typeof u === 'string') {
        username = u;
      } else if (u && typeof u === 'object') {
        username = u.username || u.name || JSON.stringify(u);
        role = u.role || 'analyst';
      }
      var isAdmin = role === 'admin';
      var safeUser = escapeHtml(username);
      // L'attribut data-u est lu par le handler via getAttribute : l'attribut
      // onclick est délimité par des apostrophes pour ne pas être coupé par les
      // guillemets internes (bug précédent : onclick="...(\"data-u\")" cassait).
      html += '<div class="report-item" style="margin-bottom:8px">';
      html +=   '<div style="width:28px;height:28px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;flex-shrink:0;color:' + (isAdmin ? 'var(--accent)' : 'var(--text2)') + '">' + (isAdmin ? '<svg class="icon" style="width:14px;height:14px"><use href="#icon-crown"/></svg>' : '<svg class="icon" style="width:14px;height:14px"><use href="#icon-user"/></svg>') + '</div>';
      html +=   '<div style="flex:1;min-width:0;font-family:var(--mono);font-size:13px">';
      html +=     '<strong>' + safeUser + '</strong>';
      html +=     ' <span class="vuln-badge ' + (isAdmin ? 'vuln-critical' : 'vuln-info') + '">' + escapeHtml(role) + '</span>';
      html +=   '</div>';
      html +=   '<div style="display:flex;gap:8px;flex-shrink:0">';
      // Le mot de passe du compte admin par défaut n'est modifiable que par
      // lui-même : on cache le bouton « Changer mdp » de sa ligne pour les autres
      // admins (le backend renvoie 403 dans tous les cas, cf. change_password).
      if (username !== 'admin' || ST.user === 'admin') {
        html +=   '<button class="btn btn-warning" style="padding:6px 12px" onclick=\'promptChangePassword(this.getAttribute("data-u"))\' data-u="' + safeUser + '">Changer mdp</button>';
      }
      // Pas de bouton Supprimer pour : le compte admin par défaut (bootstrap,
      // indélébile) ni pour SON PROPRE compte (un admin ne se supprime pas
      // lui-même). Le backend applique les deux mêmes garde-fous (cf. delete_user).
      if (username !== 'admin' && username !== ST.user) {
        html +=   '<button class="btn btn-danger" style="padding:6px 12px" onclick=\'deleteUser(this.getAttribute("data-u"))\' data-u="' + safeUser + '">Supprimer</button>';
      }
      html +=   '</div>';
      html += '</div>';
    }
    container.innerHTML = html;
  } catch(e) {
    container.innerHTML = '<div class="alert alert-err">Erreur: ' + e.message + '</div>';
  }
}

async function createUser() {
  var username = document.getElementById('new-user-name').value.trim();
  var password = document.getElementById('new-user-pass').value;
  var msg = document.getElementById('user-create-msg');
  if (!username || !password) { showMsg(msg, 'Remplis les deux champs', false); return; }
  try {
    var role = document.getElementById('new-user-role') ? document.getElementById('new-user-role').value : 'analyst';
    var res = await apiFetch('/api/users', { method:'POST', body: JSON.stringify({username:username, password:password, role:role}) });
    var data = await res.json();
    if (data.ok) {
      showMsg(msg, '[OK] Utilisateur ' + username + ' cree', true);
      document.getElementById('new-user-name').value = '';
      document.getElementById('new-user-pass').value = '';
      loadUsers();
    } else {
      showMsg(msg, '[!] ' + data.error, false);
    }
  } catch(e) { showMsg(msg, '[!] ' + e.message, false); }
}

async function deleteUser(username) {
  if (!(await uiConfirm('Supprimer l\'utilisateur ' + username + ' ?', {title:'Supprimer l\'utilisateur', okText:'Supprimer'}))) return;
  try {
    var res = await apiFetch('/api/users/' + username, { method:'DELETE' });
    var data = await res.json();
    if (data.ok) loadUsers();
    else uiAlert(data.error);
  } catch(e) { uiAlert(e.message); }
}

async function promptChangePassword(username) {
  var newPass = await uiPrompt('Nouveau mot de passe pour ' + username + ' (min 6 caracteres) :', '', {title:'Changer le mot de passe', okText:'Modifier'});
  if (!newPass) return;
  if (newPass.length < 6) { uiAlert('Trop court (min 6 caracteres)'); return; }
  apiFetch('/api/users/' + username + '/password', { method:'PUT', body: JSON.stringify({password:newPass}) })
    .then(function(res) { return res.json(); })
    .then(function(data) { uiAlert(data.ok ? 'Mot de passe modifie !' : data.error); })
    .catch(function(e) { uiAlert(e.message); });
}

async function changeMyPassword() {
  var newPass = document.getElementById('my-new-pass').value;
  var msg = document.getElementById('pass-change-msg');
  if (!newPass || newPass.length < 6) { showMsg(msg, 'Minimum 6 caracteres', false); return; }
  try {
    var res = await apiFetch('/api/users/' + ST.user + '/password', { method:'PUT', body: JSON.stringify({password:newPass}) });
    var data = await res.json();
    showMsg(msg, data.ok ? '[OK] Mot de passe modifie' : '[!] ' + data.error, data.ok);
    if (data.ok) document.getElementById('my-new-pass').value = '';
  } catch(e) { showMsg(msg, '[!] ' + e.message, false); }
}

function showMsg(el, text, ok) {
  el.style.display = 'block';
  el.style.color = ok ? 'var(--green)' : 'var(--red)';
  el.textContent = text;
  setTimeout(function() { el.style.display = 'none'; }, 4000);
}

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────
async function loadAuditLog() {
  var t = document.getElementById('audit-terminal');
  t.innerHTML = '<span class="terminal-ph">> Chargement...</span>';
  try {
    var res = await apiFetch('/api/audit');
    if (res.status === 403) {
      t.innerHTML = '<span class="t-warn">Acces reserve a l admin.</span>';
      return;
    }
    var data = await res.json();
    var lines = data.lines || [];
    if (!lines.length) {
      t.innerHTML = '<span class="terminal-ph">> Aucun log disponible.</span>';
      return;
    }
    t.innerHTML = '';
    lines.reverse().forEach(function(line) {
      var d = document.createElement('div');
      d.textContent = line;
      if (/LOGIN_OK|SERVER_START/.test(line)) d.className = 't-ok';
      else if (/LOGIN_FAIL|LOGIN_BLOCKED|RATE_LIMIT/.test(line)) d.className = 't-err';
      else if (/LOGOUT|PASSWORD_CHANGED/.test(line)) d.className = 't-warn';
      else if (/NMAP|DNS|ENUM4LINUX|NIKTO|SQLMAP|EXPLOIT/.test(line)) d.className = 't-port';
      else if (/REPORT/.test(line)) d.className = 't-info';
      else d.className = 't-dim';
      t.appendChild(d);
    });
    t.scrollTop = 0;
    addActivity('clipboard-list', 'Audit log consulte', 'var(--text2)');
  } catch(e) {
    t.innerHTML = '<span class="t-err">[!] Erreur: ' + e.message + '</span>';
  }
}

// ── PARAMETRES (admin) ───────────────────────────────────────────────────
async function loadSettings() {
  var input = document.getElementById('settings-subnets');
  var status = document.getElementById('settings-subnets-status');
  if (!input) return;
  try {
    var res = await apiFetch('/api/settings/subnets');
    if (res.status === 403) {
      status.innerHTML = '<span class="t-warn">Acces reserve a l admin.</span>';
      return;
    }
    var data = await res.json();
    input.value = data.allowed_exploit_subnets || '';
  } catch(e) {
    status.innerHTML = '<span class="t-err">[!] Erreur: ' + e.message + '</span>';
  }
}

async function saveSettingsSubnets() {
  var input = document.getElementById('settings-subnets');
  var btn = document.getElementById('settings-subnets-btn');
  var status = document.getElementById('settings-subnets-status');
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  status.innerHTML = '[*] Enregistrement...';
  try {
    var res = await apiFetch('/api/settings/subnets', { method:'PUT', body: JSON.stringify({ subnets: input.value.trim() }) });
    var data = await res.json();
    if (!res.ok || data.error) {
      status.innerHTML = '<span class="t-err">[!] ' + (data.error || 'Erreur inconnue') + '</span>';
      btn.disabled = false;
      return;
    }
    status.innerHTML = '<span class="t-ok">[+] Sous-reseaux mis a jour: ' + (data.allowed_exploit_subnets.join(', ') || '(aucun)') + '</span>';
    addActivity('sliders', 'Sous-reseaux labo mis a jour', 'var(--accent)');
    btn.disabled = false;
  } catch(e) {
    status.innerHTML = '<span class="t-err">[!] ' + e.message + '</span>';
    btn.disabled = false;
  }
}


// ── GRAPHIQUES DASHBOARD (Canvas pur — pas de dépendance externe) ────────────
var scanKPIs = [];
var vulnData = {crit:0, high:0, med:0, low:0};

// ── GRAPHIQUES (Chart.js) ───────────────────────────────────────────────────
// Remplace les anciens canvas dessinés à la main (qui paraissaient pixelisés/
// étirés en grand écran et ne se mettaient à jour qu'au refresh). Chart.js gère
// nativement le rendu net en DPR, le responsive (1280 → 2560+), les tooltips au
// survol et les animations. Vendu en local (static/vendor/chart.umd.min.js),
// aucun CDN à l'exécution — l'outil reste utilisable hors-ligne.
var _activityChart = null;
var _vulnChart = null;
var _MODULE_COLORS = {NMAP:'#b9f23c', SMB:'#56d364', HYDRA:'#ff7b72', NIKTO:'#d2a8ff',
                      SQLMAP:'#ffa657', OPENVAS:'#ff5757', MSF:'#79c0ff', EXPLOIT:'#ff7b72',
                      JOHN:'#d2a8ff', RECON:'#56d364'};

function initCharts() {
  if (typeof Chart === 'undefined') return; // garde-fou si le vendor n'a pas chargé
  Chart.defaults.color = '#8b8d90';
  Chart.defaults.font.family = "Inter, -apple-system, system-ui, sans-serif";
  Chart.defaults.font.size = 11;
  Chart.defaults.animation.duration = 600;
}

// Graphe "Activité des scans" : barres horizontales = découvertes RÉELLES par
// scan récent (ports/hôtes/identifiants). Tooltip = valeur + cible + durée + heure.
function renderActivityChart(kpis) {
  var canvas = document.getElementById('activity-chart');
  if (!canvas || typeof Chart === 'undefined') return;
  var rows = (kpis || []).slice(0, 7); // plus récents en premier
  var noMsg = document.getElementById('no-activity-msg');
  var box = canvas.closest('.chart-box');
  if (!rows.length) {
    if (_activityChart) { _activityChart.destroy(); _activityChart = null; }
    if (box) box.style.display = 'none';
    if (noMsg) noMsg.style.display = 'block';
    return;
  }
  if (box) box.style.display = 'block';
  if (noMsg) noMsg.style.display = 'none';

  var labels = rows.map(function(k) {
    var tgt = (k.target || '');
    if (tgt.length > 20) tgt = tgt.substring(0, 19) + '…';
    return k.action + ' · ' + tgt;
  });
  var data = rows.map(function(k) { return k.found || 0; });
  var colors = rows.map(function(k) { return _MODULE_COLORS[k.action] || '#b9f23c'; });

  if (_activityChart) {
    _activityChart.data.labels = labels;
    _activityChart.data.datasets[0].data = data;
    _activityChart.data.datasets[0].backgroundColor = colors;
    _activityChart.$rows = rows;
    _activityChart.update();
    return;
  }
  _activityChart = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: { labels: labels, datasets: [{
      data: data, backgroundColor: colors, borderRadius: 5,
      borderSkipped: false, barThickness: 14, maxBarThickness: 18 }] },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      layout: { padding: { right: 12 } },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d0e10', borderColor: '#2a2c30', borderWidth: 1,
          titleColor: '#f4f5f3', bodyColor: '#b9bbc0', padding: 10, cornerRadius: 8,
          displayColors: false,
          callbacks: {
            title: function(items) {
              var k = (_activityChart && _activityChart.$rows && _activityChart.$rows[items[0].dataIndex]) || {};
              return k.action + ' → ' + (k.target || '');
            },
            label: function(item) {
              var k = (_activityChart && _activityChart.$rows && _activityChart.$rows[item.dataIndex]) || {};
              return (k.found || 0) + ' ' + (k.foundLabel || 'résultats');
            },
            afterLabel: function(item) {
              var k = (_activityChart && _activityChart.$rows && _activityChart.$rows[item.dataIndex]) || {};
              return (k.elapsed != null ? 'Durée : ' + k.elapsed + 's' : '') + (k.time ? '   ' + k.time : '');
            }
          }
        }
      },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0, color: '#5c5e62' },
             grid: { color: 'rgba(255,255,255,.05)' }, border: { display: false } },
        y: { ticks: { color: '#c9cbd0', font: { weight: '600' } },
             grid: { display: false }, border: { display: false } }
      }
    }
  });
  _activityChart.$rows = rows;
}

// Camembert "Vulnérabilités par sévérité" (doughnut Chart.js + tooltips).
function renderVulnChart(crit, high, med, low) {
  var canvas = document.getElementById('vuln-chart');
  if (!canvas || typeof Chart === 'undefined') return;
  var total = crit + high + med + low;
  var noMsg = document.getElementById('no-vulns-msg');
  if (total === 0) {
    if (_vulnChart) { _vulnChart.destroy(); _vulnChart = null; }
    if (noMsg) noMsg.style.display = 'block';
    canvas.style.display = 'none';
    return;
  }
  if (noMsg) noMsg.style.display = 'none';
  canvas.style.display = 'block';
  var data = [crit, high, med, low];
  var colors = ['#ff5757', '#ff9500', '#ffd60a', '#b9f23c'];
  if (_vulnChart) {
    _vulnChart.data.datasets[0].data = data;
    _vulnChart.update();
    return;
  }
  _vulnChart = new Chart(canvas.getContext('2d'), {
    type: 'doughnut',
    data: { labels: ['Critique', 'Élevé', 'Moyen', 'Faible'],
            datasets: [{ data: data, backgroundColor: colors, borderColor: '#131415',
                         borderWidth: 2, hoverOffset: 6 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '62%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d0e10', borderColor: '#2a2c30', borderWidth: 1,
          titleColor: '#f4f5f3', bodyColor: '#b9bbc0', padding: 8, cornerRadius: 8,
          callbacks: { label: function(item) { return ' ' + item.label + ' : ' + item.parsed; } }
        }
      }
    }
  });
}

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function easeOutCubic(p) { return 1 - Math.pow(1 - p, 3); }

// Délégateurs rétro-compat : les anciens noms restent appelés ailleurs dans le
// fichier ; ils pilotent désormais Chart.js (l'animation est gérée nativement).
function animateDonut(canvasId, crit, high, med, low) { renderVulnChart(crit, high, med, low); }
function drawDonut(canvasId, crit, high, med, low) { renderVulnChart(crit, high, med, low); }

// Délégateurs rétro-compat (anciens noms appelés ailleurs) -> Chart.js.
function animateLineChart(canvasId, kpis) { renderActivityChart(kpis); }
function drawLineChart(canvasId, kpis) { renderActivityChart(kpis); }

function updateVulnChart(crit, high, med, low) {
  vulnData = {crit:crit, high:high, med:med, low:low};
  var lc = document.getElementById('leg-crit'); if (lc) lc.textContent = crit;
  var lh = document.getElementById('leg-high'); if (lh) lh.textContent = high;
  var lm = document.getElementById('leg-med');  if (lm) lm.textContent = med;
  var ll = document.getElementById('leg-low');  if (ll) ll.textContent = low;
  renderVulnChart(crit, high, med, low);
  saveDashboardStats();
}

// Extrait le nombre de "découvertes" réelles d'un scan à partir de sa sortie
// texte, pour que le graphe du dashboard reflète des résultats concrets
// (ports/hôtes/identifiants) au lieu d'une courbe basée sur l'index. Retourne
// {count, label} — count=0 reste une info valable (scan lancé, rien trouvé).
function scanDiscovery(action, output) {
  output = output || '';
  if (action === 'NMAP') {
    var ports = (output.match(/^\s*\d+\/(tcp|udp)\s+open/gim) || []).length;
    return {count: ports, label: ports === 1 ? 'port' : 'ports'};
  }
  if (action === 'SMB') {
    // enum4linux-ng marque chaque trouvaille positive par "[+] ...".
    var hits = (output.match(/^\s*\[\+\]/gim) || []).length;
    return {count: hits, label: hits === 1 ? 'trouvaille' : 'trouvailles'};
  }
  if (action === 'HYDRA') {
    // hydra imprime une ligne "[port][service] host: ... login: ... password: ..."
    // par identifiant valide trouvé.
    var creds = (output.match(/^\s*\[\d+\]\[\w+\]\s+host:/gim) || []).length;
    return {count: creds, label: creds === 1 ? 'identifiant' : 'identifiants'};
  }
  return {count: 0, label: 'résultats'};
}

function addScanKPI(action, target, elapsed, found, foundLabel) {
  found = (typeof found === 'number' && found >= 0) ? found : 0;
  scanKPIs.unshift({
    action:action, target:target, elapsed:elapsed,
    found:found, foundLabel:foundLabel || 'résultats',
    time:new Date().toLocaleTimeString('fr-FR')
  });
  if (scanKPIs.length > 20) scanKPIs.pop();
  renderKPITable();
  renderActivityChart(scanKPIs);
  saveDashboardStats();
}

function renderKPITable() {
  var el = document.getElementById('kpi-table');
  if (!el || !scanKPIs.length) return;
  var rows = scanKPIs.map(function(k) {
    var color = k.elapsed > 60 ? 'var(--orange)' : k.elapsed > 10 ? 'var(--yellow)' : 'var(--green)';
    var found = (typeof k.found === 'number') ? k.found : 0;
    var fColor = found > 0 ? 'var(--accent)' : 'var(--text3)';
    return '<tr>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:11px;color:var(--text3)">' + k.time + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--sans);font-weight:600;font-size:11px;color:var(--accent)">' + k.action + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--sans);font-size:12px">' + k.target + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:12px;color:' + fColor + ';font-weight:700">' + found + ' ' + (k.foundLabel || '') + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:12px;color:' + color + ';font-weight:700">' + k.elapsed + 's</td>' +
      '</tr>';
  }).join('');
  el.innerHTML = '<table class="result-table" style="width:100%">' +
    '<thead><tr><th>Heure</th><th>Module</th><th>Cible</th><th>Résultats</th><th>Durée</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>';
}

// ── HYDRA ─────────────────────────────────────────────────────────────────────
// Remplit le menu Wordlist depuis /api/hydra/wordlists : listes intégrées
// (toujours présentes) + fichiers détectés sur le système (rockyou…), grisés
// si absents. Non bloquant si l'API échoue (le <option> "Commune" reste).
async function loadHydraWordlists() {
  var sel = document.getElementById('hydra-wordlist');
  if (!sel) return;
  try {
    var res = await apiFetch('/api/hydra/wordlists');
    var data = await res.json();
    var wls = data.wordlists || [];
    if (!wls.length) return;
    sel.innerHTML = '';
    wls.forEach(function(w) {
      var o = document.createElement('option');
      o.value = w.id;
      var cnt = (typeof w.count === 'number') ? ' (' + w.count.toLocaleString('fr-FR') + ')' : '';
      o.textContent = w.label + cnt + (w.available ? '' : ' — indisponible');
      if (!w.available) o.disabled = true;
      sel.appendChild(o);
    });
    // Listes de noms d'utilisateur (-L) : intégrées + fichiers système.
    var usel = document.getElementById('hydra-userlist');
    var uls = data.userlists || [];
    if (usel && uls.length) {
      usel.innerHTML = '';
      uls.forEach(function(u) {
        var o = document.createElement('option');
        o.value = u.id;
        o.setAttribute('data-builtin', u.builtin ? '1' : '0');
        var cnt = (typeof u.count === 'number') ? ' (' + u.count.toLocaleString('fr-FR') + ')' : '';
        o.textContent = u.label + cnt + (u.available ? '' : ' — indisponible');
        if (!u.available) o.disabled = true;
        usel.appendChild(o);
      });
    }
  } catch(e) { /* API indisponible : on garde l'option par défaut */ }
}

// Affiche le bon champ utilisateur selon la source choisie (single/list/custom).
function onHydraUserSource() {
  var src = document.getElementById('hydra-user-source').value;
  document.getElementById('hydra-user-single-wrap').style.display = (src === 'single') ? '' : 'none';
  document.getElementById('hydra-user-list-wrap').style.display   = (src === 'list')   ? '' : 'none';
  document.getElementById('hydra-user-custom-wrap').style.display = (src === 'custom') ? '' : 'none';
}

async function runHydra() {
  var target   = document.getElementById('hydra-target').value.trim();
  var service  = document.getElementById('hydra-service').value;
  var wordlist = document.getElementById('hydra-wordlist').value;
  if (!target) return uiAlert('Entrez une cible.');

  // Source du/des nom(s) d'utilisateur : single (-l), liste (-L intégrée/système)
  // ou fichier personnalisé (-L chemin).
  var src = document.getElementById('hydra-user-source').value;
  var body = {target:target, service:service, wordlist:wordlist};
  var userLabel = '';
  if (src === 'single') {
    var username = document.getElementById('hydra-username').value.trim() || 'admin';
    body.user_source = 'single'; body.username = username;
    userLabel = username;
  } else if (src === 'list') {
    var usel = document.getElementById('hydra-userlist');
    if (!usel.value) return uiAlert('Aucune liste d\'utilisateurs disponible.');
    var opt = usel.options[usel.selectedIndex];
    body.user_source = (opt && opt.getAttribute('data-builtin') === '1') ? 'builtin' : 'filelist';
    body.userlist = usel.value;
    userLabel = 'liste:' + usel.value;
  } else {
    var path = document.getElementById('hydra-userlist-path').value.trim();
    if (!path) return uiAlert('Entrez le chemin du fichier de noms d\'utilisateur.');
    body.user_source = 'custom'; body.custom_userlist = path;
    userLabel = path;
  }

  var btn = document.getElementById('hydra-btn');
  btn.disabled = true; document.getElementById('nmap-stop-btn').style.display = 'inline-block';
  var stop = progressStart('hydra-pb','hydra-fill',30000);
  termSet('hydra-out', '[*] Hydra → ' + target + ' (' + service + ')\n[*] User: ' + userLabel + '\n[*] En cours...');
  try {
    var res = await apiFetch('/api/hydra', {
      method:'POST',
      body: JSON.stringify(body)
    });
    var data = await res.json();
    if (data.error) {
      termSet('hydra-out', '[!] ' + data.error + (data.install ? '\nInstall: ' + data.install : ''));
    } else {
      termSet('hydra-out', data.output);
      if (data.elapsed) { var hd = scanDiscovery('HYDRA', data.output); addScanKPI('HYDRA', target, data.elapsed, hd.count, hd.label); }
      renderHydraCreds(data.output, target, service);
    }
    ST.stats.scans++;
    addActivity('key', 'Hydra → ' + target + ' (' + service + ')', 'var(--red)');
    updateDashboard();
  } catch(e) { termSet('hydra-out', '[!] ' + e.message); }
  stop(); btn.disabled = false;
  stop(); btn.disabled = false;
}

// Parse les identifiants trouvés dans la sortie Hydra et propose, pour SSH,
// d'ouvrir une vraie session Metasploit (Improvement 2). Format Hydra :
// "[22][ssh] host: H   login: L   password: P".
function renderHydraCreds(output, target, service) {
  var card = document.getElementById('hydra-creds-card');
  var box = document.getElementById('hydra-creds');
  if (!card || !box) return;
  var re = /\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S*)/gi;
  var creds = [], m;
  while ((m = re.exec(output || '')) !== null) {
    creds.push({port: m[1], service: m[2].toLowerCase(), host: m[3], login: m[4], password: m[5] || ''});
  }
  if (!creds.length) { card.style.display = 'none'; box.innerHTML = ''; return; }
  box.innerHTML = creds.map(function(c, i) {
    var canSession = (c.service === 'ssh');
    var btn = canSession
      ? '<button class="btn btn-primary" style="padding:6px 12px" id="hydra-sess-btn-' + i + '" onclick=\'openHydraSession(' + i + ')\'><svg class="icon" style="width:13px;height:13px"><use href="#icon-monitor"/></svg> Ouvrir une session</button>'
      : '<span style="font-size:11px;color:var(--text3)">Session SSH uniquement</span>';
    return '<div class="report-item" style="margin-bottom:8px">' +
      '<div style="width:28px;height:28px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--green)"><svg class="icon" style="width:14px;height:14px"><use href="#icon-key"/></svg></div>' +
      '<div style="flex:1;min-width:0;font-family:var(--mono);font-size:13px"><strong style="color:var(--green)">' + escapeHtml(c.login) + '</strong> : ' + escapeHtml(c.password || '(vide)') +
      ' <span class="vuln-badge vuln-info">' + escapeHtml(c.service) + '</span> <span style="color:var(--text3)">' + escapeHtml(c.host) + ':' + escapeHtml(c.port) + '</span></div>' +
      '<div style="flex-shrink:0">' + btn + '</div></div>';
  }).join('');
  // Conserve les creds pour openHydraSession (indexées).
  ST._hydraCreds = creds.map(function(c){ return {target: c.host || target, service: c.service, username: c.login, password: c.password, port: c.port}; });
  card.style.display = 'block';
}

async function openHydraSession(i) {
  var c = (ST._hydraCreds || [])[i];
  if (!c) return;
  var btn = document.getElementById('hydra-sess-btn-' + i);
  if (btn) { btn.disabled = true; btn.textContent = 'Ouverture…'; }
  try {
    var res = await apiFetch('/api/hydra/open-session', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(c) });
    var data = await res.json();
    if (data.ok && data.session_id) {
      notify('Session #' + data.session_id + ' ouverte (' + c.username + '@' + c.target + ')', 'success');
      loadSessionCount();
      var ok = await uiConfirm('Session #' + data.session_id + ' ouverte sur ' + c.target + '. Aller à la page Sessions ?',
        { title: 'Session ouverte', okText: 'Voir les sessions', cancelText: 'Rester' });
      if (ok) { showPage('sessions'); loadSessions(); }
    } else {
      uiAlert(data.error || 'Échec de l\'ouverture de session.', { title: 'Échec', danger: true });
    }
  } catch(e) {
    uiAlert(e.message, { title: 'Erreur réseau', danger: true });
  }
  if (btn) { btn.disabled = false; btn.innerHTML = '<svg class="icon" style="width:13px;height:13px"><use href="#icon-monitor"/></svg> Ouvrir une session'; }
}

// ── CRACKING (John the Ripper) ────────────────────────────────────────────────
// Remplit le sélecteur de wordlist du Cracking depuis /api/hydra/wordlists
// (mêmes fichiers détectés : rockyou…). Liste les fichiers disponibles ; grise
// les absents.
async function loadJohnWordlists() {
  var sel = document.getElementById('john-wordlist');
  if (!sel) return;
  try {
    var res = await apiFetch('/api/hydra/wordlists');
    var data = await res.json();
    var files = (data.wordlists || []).filter(function(w){ return !w.builtin; });
    if (!files.length) return;
    sel.innerHTML = '';
    files.forEach(function(w) {
      var o = document.createElement('option');
      o.value = w.id;
      var cnt = (typeof w.count === 'number') ? ' (' + w.count.toLocaleString('fr-FR') + ')' : '';
      o.textContent = w.label + cnt + (w.available ? '' : ' — indisponible');
      if (!w.available) o.disabled = true;
      sel.appendChild(o);
    });
  } catch(e) { /* garde l'option par défaut */ }
}

// Charge un fichier de hashes dans le textarea (lecture côté client).
function loadHashFile(event) {
  var file = event.target.files && event.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) { document.getElementById('john-hashes').value = e.target.result; };
  reader.readAsText(file);
}

var _johnCrackedCount = 0;
function renderCracked(creds) {
  var el = document.getElementById('john-cracked');
  if (!el) return;
  if (!creds || !creds.length) {
    el.innerHTML = '<div style="color:var(--text3);font-family:var(--sans);font-size:12px">Aucun hash cassé pour l\'instant.</div>';
    _johnCrackedCount = 0;
    return;
  }
  // Bannière de succès quand de nouveaux hash sont cassés (déduplication par
  // nombre, car renderCracked est rappelé à chaque tick de polling).
  if (creds.length > _johnCrackedCount) {
    var last = creds[creds.length - 1];
    notify('Hash cassé : ' + ((last.user && last.user !== '?' && last.user !== '(hash)') ? last.user + ' / ' : '') + last.password, 'success');
  }
  _johnCrackedCount = creds.length;
  var html = '';
  creds.forEach(function(c) {
    var u = (c.user && c.user !== '?' && c.user !== '(hash)') ? escapeHtml(c.user) : '—';
    html += '<div class="report-item" style="margin-bottom:8px">';
    html +=   '<div style="width:28px;height:28px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--accent)"><svg class="icon" style="width:14px;height:14px"><use href="#icon-key"/></svg></div>';
    html +=   '<div style="flex:1;min-width:0;font-family:var(--mono);font-size:13px">Utilisateur : <strong>' + u + '</strong></div>';
    html +=   '<div style="font-family:var(--mono);font-size:13px"><span class="vuln-badge vuln-critical">' + escapeHtml(c.password) + '</span></div>';
    html += '</div>';
  });
  el.innerHTML = html;
}

async function runJohn() {
  var hashes = document.getElementById('john-hashes').value.trim();
  if (!hashes) return uiAlert('Collez au moins un hash (ou chargez un fichier).');
  var body = {
    hashes: hashes,
    format: document.getElementById('john-format').value,
    rules:  document.getElementById('john-rules').value,
  };
  var custom = document.getElementById('john-wordlist-path').value.trim();
  if (custom) body.custom_wordlist = custom;
  else body.wordlist = document.getElementById('john-wordlist').value;

  var btn = document.getElementById('john-btn');
  btn.disabled = true;
  document.getElementById('john-stop-btn').style.display = 'inline-block';
  var stop = progressStart('john-pb','john-fill',20000);
  termSet('john-out', '[*] Lancement de John the Ripper…');
  renderCracked([]);
  try {
    var res = await apiFetch('/api/john/start', { method:'POST', body: JSON.stringify(body) });
    var data = await res.json();
    if (data.error) {
      termSet('john-out', '[!] ' + data.error + (data.install ? '\nInstall: ' + data.install : ''));
      stop(); btn.disabled = false; document.getElementById('john-stop-btn').style.display = 'none';
      return;
    }
    ST.johnJobId = data.job_id;
    termSet('john-out', '[*] Commande: ' + data.command + '\n[*] Job ' + data.job_id + ' — cracking en cours…');
    await pollJohn(data.job_id, stop, btn);
  } catch(e) {
    termSet('john-out', '[!] ' + e.message);
    stop(); btn.disabled = false; document.getElementById('john-stop-btn').style.display = 'none';
  }
}

// Poll l'avancement du job john toutes les ~1.5s : affiche les identifiants
// déchiffrés au fur et à mesure + le log live, jusqu'à la fin (ou l'arrêt).
async function pollJohn(jobId, stop, btn) {
  while (ST.johnJobId === jobId) {
    await sleep(1500);
    if (ST.johnJobId !== jobId) break;  // stoppé entre-temps
    var res, data;
    try {
      res = await apiFetch('/api/john/status/' + jobId);
      data = await res.json();
    } catch(e) { continue; }
    if (data.error) { termSet('john-out', '[!] ' + data.error); break; }
    renderCracked(data.cracked);
    var head = '[*] Job ' + jobId + ' — ' + (data.running ? 'en cours' : 'terminé') + ' (' + data.elapsed + 's)\n';
    head += '[*] ' + (data.cracked ? data.cracked.length : 0) + ' hash(es) cassé(s)\n\n';
    termSet('john-out', head + (data.log || ''));
    if (!data.running) {
      if (data.cracked && data.cracked.length) {
        addActivity('hash', 'John → ' + data.cracked.length + ' hash(es) cassé(s)', 'var(--accent)');
        ST.stats.scans++; updateDashboard();
      }
      break;
    }
  }
  if (stop) stop();
  if (btn) btn.disabled = false;
  document.getElementById('john-stop-btn').style.display = 'none';
  if (ST.johnJobId === jobId) ST.johnJobId = null;
}

async function stopJohn() {
  var jobId = ST.johnJobId;
  if (!jobId) return;
  ST.johnJobId = null;  // stoppe la boucle de polling
  try {
    await apiFetch('/api/john/stop/' + jobId, { method:'POST' });
    termSet('john-out', '[■] Cracking arrêté par l\'utilisateur.');
  } catch(e) { /* best-effort */ }
  document.getElementById('john-btn').disabled = false;
  document.getElementById('john-stop-btn').style.display = 'none';
}

// ── SESSIONS POST-EXPLOITATION (Metasploit) ───────────────────────────────────
async function loadSessions() {
  var el = document.getElementById('sessions-list');
  var lhostEl = document.getElementById('sessions-lhost');
  if (!el) return;
  el.innerHTML = '<div style="color:var(--text3);font-family:var(--sans);font-size:12px">Chargement…</div>';
  try {
    var res = await apiFetch('/api/sessions');
    var data = await res.json();
    if (lhostEl && data.lhost) lhostEl.textContent = data.lhost;
    if (data.error) {
      el.innerHTML = '<div class="alert alert-warn"><svg class="icon" style="width:16px;height:16px;flex-shrink:0"><use href="#icon-alert-triangle"/></svg><div>' + escapeHtml(data.error) + '</div></div>';
      return;
    }
    var sessions = data.sessions || [];
    setSessionCount(sessions.length);
    if (!sessions.length) {
      el.innerHTML = '<div style="color:var(--text3);font-family:var(--sans);font-size:12px">Aucune session active. Ouvrez une session via un module exploit (page <strong>Metasploit</strong>, ex : vsftpd 2.3.4 backdoor), puis rafraîchissez.</div>';
      document.getElementById('session-console-card').style.display = 'none';
      ST.sessionId = null;
      return;
    }
    var html = '';
    sessions.forEach(function(s) {
      var label = (s.type || 'shell') + ' → ' + (s.target || '?');
      html += '<div class="report-item" style="margin-bottom:8px">';
      html +=   '<div style="width:28px;height:28px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--accent)"><svg class="icon" style="width:14px;height:14px"><use href="#icon-monitor"/></svg></div>';
      html +=   '<div style="flex:1;min-width:0;font-family:var(--mono);font-size:13px">';
      html +=     '<strong>#' + escapeHtml(s.id) + '</strong> <span class="vuln-badge vuln-info">' + escapeHtml(s.type || 'shell') + '</span> ' + escapeHtml(s.target || '');
      if (s.via_exploit) html += '<div style="color:var(--text3);font-size:11px;margin-top:2px">' + escapeHtml(s.via_exploit) + (s.username ? ' — ' + escapeHtml(s.username) : '') + '</div>';
      html +=   '</div>';
      html +=   '<div style="display:flex;gap:8px;flex-shrink:0">';
      html +=     '<button class="btn btn-primary" style="padding:6px 12px" onclick=\'selectSession(this.getAttribute("data-sid"), this.getAttribute("data-label"))\' data-sid="' + escapeHtml(s.id) + '" data-label="' + escapeHtml(label) + '">Console</button>';
      html +=     '<button class="btn btn-danger" style="padding:6px 12px" onclick=\'killSession(this.getAttribute("data-sid"))\' data-sid="' + escapeHtml(s.id) + '">Tuer</button>';
      html +=   '</div>';
      html += '</div>';
    });
    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = '<div class="alert alert-err">Erreur: ' + escapeHtml(e.message) + '</div>';
  }
}

function selectSession(sid, label) {
  ST.sessionId = sid;
  document.getElementById('session-console-card').style.display = 'block';
  document.getElementById('session-console-id').textContent = '#' + sid + (label ? ' — ' + label : '');
  termSet('session-out', '> Session ' + sid + ' sélectionnée. Commandes exécutées sur la cible réelle (ex : id, uname -a, whoami).');
  document.getElementById('session-cmd').focus();
}

async function sendSessionCmd() {
  var sid = ST.sessionId;
  if (!sid) return uiAlert('Sélectionnez d\'abord une session.');
  var inp = document.getElementById('session-cmd');
  var cmd = inp.value.trim();
  if (!cmd) return;
  termAppend('session-out', '$ ' + cmd);
  inp.value = '';
  try {
    var res = await apiFetch('/api/sessions/' + sid + '/exec', { method:'POST', body: JSON.stringify({command: cmd}) });
    var data = await res.json();
    if (data.error) termAppend('session-out', '[!] ' + data.error);
    else termAppend('session-out', data.output);
  } catch(e) { termAppend('session-out', '[!] ' + e.message); }
}

async function killSession(sid) {
  if (!(await uiConfirm('Fermer la session ' + sid + ' ? Cette action est irréversible.', {title:'Fermer la session', okText:'Fermer', danger:true}))) return;
  try {
    var res = await apiFetch('/api/sessions/' + sid + '/kill', { method:'POST' });
    var data = await res.json();
    if (data.error) { uiAlert(data.error, {title:'Erreur', danger:true}); return; }
    if (ST.sessionId === sid) { ST.sessionId = null; document.getElementById('session-console-card').style.display = 'none'; }
    notify('Session ' + sid + ' fermée.', 'info');
    loadSessions();
  } catch(e) { uiAlert(e.message, {title:'Erreur', danger:true}); }
}

function closeModal() { document.getElementById('report-modal').classList.remove('open'); }
document.getElementById('report-modal').addEventListener('click', function(e){ if(e.target===this) closeModal(); });
document.addEventListener('keydown', function(e) { if(e.key==='Escape') closeModal(); });

// Chart.js gère lui-même le redimensionnement responsive (responsive:true +
// maintainAspectRatio:false) : plus besoin d'un écouteur resize manuel. On
// conserve redrawCharts() (appelé ailleurs) comme simple rafraîchissement.
function redrawCharts() {
  renderActivityChart(scanKPIs);
  renderVulnChart(vulnData.crit, vulnData.high, vulnData.med, vulnData.low);
}

// ── ARRÊTER UN SCAN ──────────────────────────────────────────────────────────
var SCAN_LABELS = {nmap:'Nmap', nikto:'Nikto', openvas:'OpenVAS', sqlmap:'SQLMap', exploit_auto:'Exploitation auto'};
async function stopScan(scanType) {
  var label = SCAN_LABELS[scanType] || scanType;
  if (!(await uiConfirm('Arrêter le scan ' + label + ' ?', {title:'Arrêter le scan', okText:'Arrêter'}))) return;
  var body = {scan: scanType};
  // OpenVAS ne tourne pas comme un process local tuable : gvmd vit dans un autre
  // conteneur. Le backend doit envoyer GMP <stop_task> -> on lui passe le job_id.
  if (scanType === 'openvas' && ST.openvasJobId) body.job_id = ST.openvasJobId;
  try {
    var res = await apiFetch('/api/stop-scan', { method:'POST', body: JSON.stringify(body) });
    var data = await res.json();
    if (data.ok) {
      uiAlert(data.message, {title:'Scan arrêté'});
      var stopBtn = document.getElementById(scanType + '-stop-btn');
      if (stopBtn) stopBtn.style.display = 'none';
    } else {
      uiAlert(data.message, {title:'Erreur', danger:true});
    }
  } catch(e) {
    uiAlert(e.message, {title:'Erreur réseau', danger:true});
  }
}


// Afficher/cacher les boutons Arrêter pour tous les scans
function showStopBtn(scanType) {
  var btn = document.getElementById(scanType + '-stop-btn');
  if (btn) btn.style.display = 'inline-block';
  var launchBtn = document.getElementById(scanType + '-btn');
  if (launchBtn) launchBtn.style.display = 'none';
}

function hideStopBtn(scanType) {
  var btn = document.getElementById(scanType + '-stop-btn');
  if (btn) btn.style.display = 'none';
  var launchBtn = document.getElementById(scanType + '-btn');
  if (launchBtn) launchBtn.style.display = 'inline-block';
}
