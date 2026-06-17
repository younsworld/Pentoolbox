
// ── STATE ─────────────────────────────────────────────────────────────────
const ST = {
  user: null,
  token: null,
  role: null,  // "admin" ou "analyst"
  stats: { vulns:0, scans:0, reports:0, hosts:0 },
  activity: [],
  lastExploit: null,
};

const sleep = ms => new Promise(r => setTimeout(r, ms));

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
    err.style.display = 'block';
    err.textContent = '⚠ Remplis les deux champs';
    return;
  }

  btn.textContent = 'Connexion...';
  btn.disabled = true;
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
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('app').style.display = 'block';
        document.getElementById('user-display').textContent = '👤 ' + data.user;
        loadSysInfo();
        loadReportCount();
      } else {
        err.style.display = 'block';
        err.textContent = '⚠ ' + (data.error || 'Identifiants incorrects');
        document.getElementById('password').value = '';
      }
    } catch(e) {
      err.style.display = 'block';
      err.textContent = '⚠ Erreur serveur: ' + xhr.responseText.substring(0, 100);
    }
  };

  xhr.onerror = function() {
    btn.textContent = 'ACCÉDER À LA PLATEFORME';
    btn.disabled = false;
    err.style.display = 'block';
    err.textContent = '⚠ Flask ne répond pas — relance python app.py';
  };

  xhr.ontimeout = function() {
    btn.textContent = 'ACCÉDER À LA PLATEFORME';
    btn.disabled = false;
    err.style.display = 'block';
    err.textContent = '⚠ Timeout — Flask trop lent à répondre';
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

// ── NAV ──────────────────────────────────────────────────────────────────
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  var page = document.getElementById('page-' + name);
  if (page) page.classList.add('active');
  if (el) el.classList.add('active');
}

function toggleCheck(el) {
  el.classList.toggle('checked');
  el.querySelector('input').checked = el.classList.contains('checked');
}

// ── TERMINAL ──────────────────────────────────────────────────────────────
function termSet(id, text) {
  var t = document.getElementById(id);
  t.innerHTML = '';
  if (!text) return;
  text.split('\n').forEach(function(line) {
    var d = document.createElement('div');
    d.textContent = line;
    if (/^\[\+\]|open|found/i.test(line)) d.className='t-ok';
    else if (/^\[!\]|error|fail|VULN|CRITICAL/i.test(line)) d.className='t-err';
    else if (/^\[~\]|warning|missing/i.test(line)) d.className='t-warn';
    else if (/^\[\*\]/i.test(line)) d.className='t-info';
    else if (/port.*tcp|port.*udp/i.test(line)) d.className='t-port';
    else d.className='t-dim';
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
  setTimeout(function() { drawLineChart('activity-chart', scanKPIs); }, 50);
  var el = document.getElementById('recent-activity');
  el.innerHTML = ST.activity.map(function(a) {
    return '<div class="recent-item"><div class="ri-dot" style="background:'+a.color+'"></div><div style="font-size:12px;font-family:var(--mono);flex:1">'+a.icon+' '+a.text+'</div><div style="font-size:11px;color:var(--text3);font-family:var(--mono)">'+a.time+'</div></div>';
  }).join('');
}

function updateDashboard() {
  document.getElementById('dash-vulns').textContent = ST.stats.vulns;
  document.getElementById('dash-scans').textContent = ST.stats.scans;
  document.getElementById('dash-reports').textContent = ST.stats.reports;
  document.getElementById('dash-hosts').textContent = ST.stats.hosts;
}

// ── SYS INFO ──────────────────────────────────────────────────────────────
async function loadSysInfo() {
  try {
    var res = await apiFetch('/api/status');
    var data = await res.json();
    document.getElementById('sys-info').textContent = data.os + ' | Python ' + data.python;
    var html = '';
    Object.entries(data.tools).forEach(function(kv) {
      html += '<div style="margin-bottom:3px"><span style="color:' + (kv[1] ? 'var(--green)' : 'var(--red)') + '">' + (kv[1] ? '✓' : '✗') + '</span> ' + kv[0] + '</div>';
    });
    document.getElementById('sidebar-tools').innerHTML = html;
    ST.stats.reports = data.reports_count;
    updateDashboard();
  } catch(e) {
    document.getElementById('sys-info').textContent = 'Flask actif';
  }
}

async function loadReportCount() {
  try {
    var res = await apiFetch('/api/status');
    var data = await res.json();
    var badge = document.getElementById('reports-badge');
    badge.style.display = data.reports_count > 0 ? 'inline-block' : 'none';
    badge.textContent = data.reports_count;
  } catch(e) {}
}

async function loadTools() {
  var container = document.getElementById('tools-content');
  try {
    var res = await apiFetch('/api/status');
    var data = await res.json();
    var toolsHtml = Object.entries(data.tools).map(function(kv) {
      return '<div class="tool-status-item"><span style="color:'+(kv[1]?'var(--green)':'var(--red))')+';">'+(kv[1]?'✓':'✗')+'</span><span style="font-weight:600">'+kv[0]+'</span><span style="color:'+(kv[1]?'var(--green)':'var(--text3))')+';">'+(kv[1]?'Disponible':'Absent')+'</span></div>';
    }).join('');
    container.innerHTML = '<div class="card"><div class="card-title">🖥 Système</div><div style="font-family:var(--mono);font-size:13px;line-height:2"><div>OS: <span style=\'color:var(--accent)\'>' + data.os + '</span></div><div>Python: <span style=\'color:var(--accent)\'>' + data.python + '</span></div></div></div><div class="card"><div class="card-title">🔧 Outils</div><div class="tool-status-grid">' + toolsHtml + '</div></div>';
  } catch(e) {
    container.innerHTML = '<div class="alert alert-err">✗ Erreur: ' + e.message + '</div>';
  }
}

// ── DNS DUMPSTER ──────────────────────────────────────────────────────────
async function runDNSDumpster() {
  var dnsStart = Date.now();
  const domain = document.getElementById('dumpster-target').value.trim();
  if (!domain) return alert('Entrez un domaine.');
  const btn = document.getElementById('dumpster-btn');
  btn.disabled = true;
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
    addActivity('🌐', `DNSDumpster → ${domain} (${data.a?.length||0} sous-domaines)`, 'var(--accent)');
  } catch(e) {
    termSet('dumpster-out', `[!] Erreur: ${e.message}`);
  }
  
  stop(); btn.disabled=false; updateDashboard();
}

function renderDNSTable(data) {
  let html = '';
  if (data.a?.length) {
    html += `<div class="dns-section-header">📍 Enregistrements A — ${data.a.length} sous-domaine(s)</div>`;
    html += `<div class="dns-row" style="color:var(--text3);font-size:10px;letter-spacing:1px;text-transform:uppercase"><span>Hôte</span><span>IP</span><span>Info</span></div>`;
    html += data.a.map(r => `<div class="dns-row"><span style="color:var(--text)">${r.host}</span><span style="color:var(--yellow)">${r.ip}</span><span style="color:var(--text3)">—</span></div>`).join('');
  }
  if (data.mx?.length) {
    html += `<div class="dns-section-header">📧 MX — ${data.mx.length} serveur(s) de messagerie</div>`;
    html += data.mx.map(r => `<div class="dns-row"><span style="color:var(--text)">${r.host}</span><span style="color:var(--yellow)">${r.ip}</span><span style="color:var(--text3)">Priorité: ${r.priority}</span></div>`).join('');
  }
  if (data.ns?.length) {
    html += `<div class="dns-section-header">🔧 NS — ${data.ns.length} nameserver(s)</div>`;
    html += data.ns.map(r => `<div class="dns-row"><span style="color:var(--text)">${r.host}</span><span style="color:var(--yellow)">${r.ip}</span><span></span></div>`).join('');
  }
  if (data.txt?.length) {
    html += `<div class="dns-section-header">📝 TXT — ${data.txt.length} enregistrement(s)</div>`;
    html += data.txt.map(r => `<div style="padding:7px 8px;font-family:var(--mono);font-size:11px;color:var(--text2);border-bottom:1px solid var(--bg3)">"${r}"</div>`).join('');
  }
  document.getElementById('dumpster-structured').innerHTML = html;
  document.getElementById('dumpster-results-card').style.display = 'block';
}

// ── DNS LOOKUP ─────────────────────────────────────────────────────────────
async function runDNS() {
  const target = document.getElementById('dns-target').value.trim();
  const type = document.getElementById('dns-type').value;
  if (!target) return alert('Entrez un domaine.');
  termSet('dns-out', `[*] DNS ${type} → ${target}...`);
  try {
    const res = await apiFetch('/api/dns', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target, type})
    });
    const data = await res.json();
    termSet('dns-out', data.output || `[!] ${data.error}`);
    ST.stats.scans++; addActivity('🔎', `DNS ${type} → ${target}`, 'var(--accent)'); updateDashboard();
  } catch(e) { termSet('dns-out', `[!] ${e.message}`); }
}

// ── ARP ─────────────────────────────────────────────────────────────────────

function renderDNSTable(data) {
  var html = '';
  if (data.a && data.a.length) {
    html += '<div class="dns-section-header">📍 Enregistrements A — ' + data.a.length + ' sous-domaine(s)</div>';
    html += '<div class="dns-row" style="color:var(--text3);font-size:10px;letter-spacing:1px;text-transform:uppercase"><span>Hôte</span><span>IP</span><span>Info</span></div>';
    html += data.a.map(function(r) { return '<div class="dns-row"><span style="color:var(--text)">' + r.host + '</span><span style="color:var(--yellow)">' + r.ip + '</span><span style="color:var(--text3)">—</span></div>'; }).join('');
  }
  if (data.mx && data.mx.length) {
    html += '<div class="dns-section-header">📧 MX — ' + data.mx.length + ' serveur(s)</div>';
    html += data.mx.map(function(r) { return '<div class="dns-row"><span style="color:var(--text)">' + r.host + '</span><span style="color:var(--yellow)">' + r.ip + '</span><span style="color:var(--text3)">Priorité: ' + r.priority + '</span></div>'; }).join('');
  }
  if (data.ns && data.ns.length) {
    html += '<div class="dns-section-header">🔧 NS — ' + data.ns.length + ' nameserver(s)</div>';
    html += data.ns.map(function(r) { return '<div class="dns-row"><span style="color:var(--text)">' + r.host + '</span><span style="color:var(--yellow)">' + r.ip + '</span><span></span></div>'; }).join('');
  }
  if (data.txt && data.txt.length) {
    html += '<div class="dns-section-header">📝 TXT</div>';
    html += data.txt.map(function(r) { return '<div style="padding:7px 8px;font-family:var(--mono);font-size:11px;color:var(--text2);border-bottom:1px solid var(--bg3)">"' + r + '"</div>'; }).join('');
  }
  document.getElementById('dumpster-structured').innerHTML = html;
  document.getElementById('dumpster-results-card').style.display = 'block';
}

// ── ARP ───────────────────────────────────────────────────────────────────

// ── ARP SCAN WINDOWS ─────────────────────────────────────────────────────────
function launchARPWindows() {
  var range = document.getElementById('arp-range').value.trim() || '192.168.1.0/24';
  
  // Instructions pour lancer le script PS
  var msg = 'Pour scanner le vrai réseau Windows :\n\n' +
    '1. Ouvre un PowerShell en ADMINISTRATEUR\n' +
    '2. Va dans le dossier PenToolbox :\n' +
    '   cd C:\\...\\pentoolbox\n' +
    '3. Lance la commande :\n' +
    '   powershell -ExecutionPolicy Bypass -File ARP_SCAN.ps1 -Range ' + range + '\n\n' +
    'Les résultats apparaîtront automatiquement ici !';
  
  alert(msg);
  
  // Affiche dans le terminal
  termSet('arp-out', 
    '[*] Scan Windows en attente...\n' +
    '[*] Lance ARP_SCAN.ps1 dans un PowerShell admin:\n\n' +
    '    powershell -ExecutionPolicy Bypass -File ARP_SCAN.ps1 -Range ' + range + '\n\n' +
    '[*] Les résultats apparaîtront ici automatiquement.'
  );
  
  // Poll toutes les 3 secondes pour voir si les résultats arrivent
  var pollCount = 0;
  var pollInterval = setInterval(async function() {
    pollCount++;
    if (pollCount > 60) { // Stop après 3 minutes
      clearInterval(pollInterval);
      return;
    }
    try {
      var res = await apiFetch('/api/arp/poll/default');
      var data = await res.json();
      if (data.done) {
        clearInterval(pollInterval);
        termSet('arp-out', data.output);
        ST.stats.scans++;
        addActivity('📡', 'ARP Windows → ' + range, 'var(--green)');
        updateDashboard();
      }
    } catch(e) {}
  }, 3000);
}

async function runARP() {
  var range = document.getElementById('arp-range').value.trim() || '192.168.1.0/24';
  var stop = progressStart('arp-pb', 'arp-fill', 90000);
  termSet('arp-out', '[*] ARP Scan -> ' + range + '\n[*] En cours... (30-90 secondes)');
  try {
    var startT = Date.now();
    var res = await apiFetch('/api/arp', { method:'POST', body: JSON.stringify({range:range}) });
    var data = await res.json();
    var elapsed = ((Date.now() - startT) / 1000).toFixed(2);
    termSet('arp-out', data.output);
    addScanKPI('ARP', range, parseFloat(elapsed));
    ST.stats.scans++; addActivity('📡', 'ARP -> ' + range, 'var(--green)'); updateDashboard();
  } catch(e) { termSet('arp-out', '[!] ' + e.message); }
  stop();
}

// ── NMAP ──────────────────────────────────────────────────────────────────
async function runNmap() {
  var target = document.getElementById('nmap-target').value.trim();
  var type = document.getElementById('nmap-type').value;
  if (!target) return alert('Entrez une cible.');
  var btn = document.getElementById('nmap-btn');
  btn.disabled = true;
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
    }
    if (data.elapsed) addScanKPI('NMAP', target, data.elapsed);
    ST.stats.scans++; addActivity('🔍', 'Nmap → ' + target, 'var(--yellow)'); updateDashboard();
  } catch(e) { termSet('nmap-out', '[!] ' + e.message); }
  stop(); btn.disabled=false;
}

// ── NIKTO ─────────────────────────────────────────────────────────────────
async function runNikto() {
  var target = document.getElementById('nikto-target').value.trim();
  if (!target) return alert('Entrez une cible.');
  var btn = document.getElementById('nikto-btn');
  btn.disabled = true;
  var stop = progressStart('nikto-pb','nikto-fill',180000);
  var extraHost = document.getElementById('nikto-host') ? document.getElementById('nikto-host').value.trim() : '';
  termSet('nikto-out', '[*] Nikto → ' + target + '\n[*] En cours... (2-5 minutes)');
  try {
    var res = await apiFetch('/api/nikto', { method:'POST', body: JSON.stringify({target:target, extra_host:extraHost}) });
    var data = await res.json();
    termSet('nikto-out', data.error ? '[!] ' + data.error + '\nInstall: ' + (data.install||'') : data.output);
    ST.stats.scans++; addActivity('🌐', 'Nikto → ' + target, 'var(--orange)'); updateDashboard();
  } catch(e) { termSet('nikto-out', '[!] ' + e.message); }
  stop(); btn.disabled=false;
}

// ── SQLMAP ────────────────────────────────────────────────────────────────
async function runSQLMap() {
  var target = document.getElementById('sqlmap-target').value.trim();
  if (!target) return alert('Entrez une URL.');
  var btn = document.getElementById('sqlmap-btn');
  btn.disabled = true;
  termSet('sqlmap-out', '[*] SQLMap → ' + target + '\n[*] En cours...');
  try {
    var res = await apiFetch('/api/sqlmap', { method:'POST', body: JSON.stringify({target:target}) });
    var data = await res.json();
    termSet('sqlmap-out', data.error ? '[!] ' + data.error + '\nInstall: ' + (data.install||'') : data.output);
    ST.stats.scans++; addActivity('💉', 'SQLMap → ' + target, 'var(--red)'); updateDashboard();
  } catch(e) { termSet('sqlmap-out', '[!] ' + e.message); }
  btn.disabled=false;
}

// ── EXPLOITATION ──────────────────────────────────────────────────────────
async function runExploit() {
  var target = document.getElementById('exploit-target').value.trim();
  if (!target) return alert('Entrez une cible.');
  var modules = [];
  document.querySelectorAll('#exploit-modules .checkbox-item.checked').forEach(function(l) {
    modules.push(l.querySelector('input').value);
  });
  if (!modules.length) return alert('Sélectionnez au moins un module.');

  document.getElementById('exploit-results-card').style.display='none';
  var btn = document.getElementById('exploit-btn');
  btn.disabled = true;
  var stop = progressStart('exploit-pb','exploit-fill',modules.length*3000);
  var termId = 'exploit-out';
  termSet(termId, '[*] Exploitation → ' + target + '\n[*] Modules: ' + modules.join(', ') + '\n' + '═'.repeat(50));

  var vulnFound = [];

  for (var mi=0; mi<modules.length; mi++) {
    await sleep(300);
    var lines = getExploitLines(modules[mi], target, vulnFound);
    for (var li=0; li<lines.length; li++) {
      await sleep(100);
      var d = document.createElement('div');
      d.textContent = lines[li];
      var l = lines[li];
      if (/^\[!\]|INJECT|VULN|CRITICAL|RCE|DÉTECTÉ/i.test(l)) d.className='t-err';
      else if (/^\[~\]/.test(l)) d.className='t-warn';
      else if (/^\[\+\]/.test(l)) d.className='t-ok';
      else if (/^\[\*\]/.test(l)) d.className='t-info';
      else if (/^\[✓\]/.test(l)) d.className='t-ok';
      else d.className='t-dim';
      var t = document.getElementById(termId);
      t.appendChild(d); t.scrollTop=t.scrollHeight;
    }
  }

  var sumDiv = document.createElement('div');
  sumDiv.className='t-warn';
  sumDiv.textContent = '═'.repeat(50) + '\n[*] ' + vulnFound.length + ' vulnérabilité(s) détectée(s)';
  document.getElementById(termId).appendChild(sumDiv);

  stop(); btn.disabled=false;

  if (vulnFound.length) {
    renderVulnTable(vulnFound, target);
    ST.stats.vulns += vulnFound.length;
    var c=0,h=0,m=0,l=0;
    vulnFound.forEach(function(v){if(v.severity==='critical')c++;else if(v.severity==='high')h++;else if(v.severity==='medium')m++;else l++;});
    updateVulnChart(c,h,m,l);
    document.getElementById('gen-report-btn').style.display='inline-block';
    addActivity('⚡', 'Exploit → ' + target + ' — ' + vulnFound.length + ' vuln(s)', 'var(--red)');
  } else {
    addActivity('⚡', 'Exploit → ' + target + ' — RAS', 'var(--green)');
    document.getElementById('gen-report-btn').style.display='none';
  }
  ST.lastExploit = { target:target, vulns:vulnFound };
  ST.stats.scans++; updateDashboard();
}

function getExploitLines(mod, target, vulnFound) {
  var L=[];
  if (mod==='http') {
    L.push('[*] Module HTTP/HTTPS (80/443) → '+target);
    var servers=['Apache/2.4.52','nginx/1.22.1','Microsoft-IIS/10.0'];
    L.push('[+] Serveur: '+servers[Math.floor(Math.random()*3)]);
    L.push('[*] Test SQL Injection...');
    if (Math.random()>.4){vulnFound.push({name:'SQL Injection (UNION-based)',severity:'critical',port:80,module:'HTTP',cve:'N/A',recommendation:'Utiliser PDO/Prepared Statements'});L.push('[!] SQL INJECTION DÉTECTÉE');}
    else L.push('[✓] SQL Injection: non vulnérable');
    L.push('[*] Test XSS...');
    if (Math.random()>.5){vulnFound.push({name:'XSS Réfléchi',severity:'high',port:80,module:'HTTP',cve:'N/A',recommendation:'Encoder les sorties HTML, CSP'});L.push('[!] XSS RÉFLÉCHI DÉTECTÉ');}
    else L.push('[✓] XSS: non vulnérable');
    var miss=['X-Frame-Options','CSP','X-Content-Type-Options'].filter(function(){return Math.random()>.5;});
    if (miss.length){vulnFound.push({name:'Headers manquants: '+miss.join(', '),severity:'low',port:80,module:'HTTP',cve:'N/A',recommendation:'Configurer les headers HTTP'});L.push('[~] Headers absents: '+miss.join(', '));}
    L.push('──────────────────────────────────');
  }
  if (mod==='smb') {
    L.push('[*] Module SMB (445) → '+target);
    L.push('[+] OS: Windows 10 x64');
    if (Math.random()>.5){vulnFound.push({name:'MS17-010 EternalBlue',severity:'critical',port:445,module:'SMB',cve:'CVE-2017-0144',recommendation:'Patch MS17-010, désactiver SMBv1'});L.push('[!] ETERNALBLUE DÉTECTÉ !!');}
    else L.push('[✓] EternalBlue: patché');
    L.push('──────────────────────────────────');
  }
  if (mod==='ftp') {
    L.push('[*] Module FTP (21) → '+target);
    if (Math.random()>.5){vulnFound.push({name:'FTP Accès anonyme',severity:'high',port:21,module:'FTP',cve:'N/A',recommendation:'Désactiver login anonyme'});L.push('[!] CONNEXION ANONYME ACCEPTÉE');}
    else L.push('[✓] Accès anonyme: refusé');
    L.push('──────────────────────────────────');
  }
  if (mod==='ssh') {
    L.push('[*] Module SSH (22) → '+target);
    L.push('[+] Bannière: OpenSSH_8.9p1');
    if (Math.random()>.7){vulnFound.push({name:'SSH creds par défaut',severity:'critical',port:22,module:'SSH',cve:'N/A',recommendation:'Supprimer creds par défaut, MFA'});L.push('[!] CREDENTIALS VALIDES: admin:admin');}
    else L.push('[✓] Creds par défaut: refusés');
    L.push('──────────────────────────────────');
  }
  if (mod==='mysql') {
    L.push('[*] Module MySQL (3306) → '+target);
    if (Math.random()>.6){vulnFound.push({name:'MySQL root sans auth',severity:'critical',port:3306,module:'MySQL',cve:'N/A',recommendation:'Configurer mot de passe root'});L.push('[!] ROOT SANS MOT DE PASSE');}
    else L.push('[✓] Auth requise');
    L.push('──────────────────────────────────');
  }
  if (mod==='rdp') {
    L.push('[*] Module RDP (3389) → '+target);
    if (Math.random()>.6){vulnFound.push({name:'BlueKeep CVE-2019-0708',severity:'critical',port:3389,module:'RDP',cve:'CVE-2019-0708',recommendation:'Appliquer KB4499175'});L.push('[!] BLUEKEEP DÉTECTÉ — CVE-2019-0708 !');}
    else L.push('[✓] BlueKeep: non vulnérable');
    L.push('──────────────────────────────────');
  }
  return L;
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
  document.getElementById('modal-content').innerHTML='<h2 style="font-size:20px;font-weight:800;margin-bottom:20px">📄 Générer un rapport</h2><div style="font-family:var(--mono);font-size:13px;color:var(--text2);margin-bottom:20px">Cible: <strong style=\'color:var(--accent)\'>' + ST.lastExploit.target + '</strong><br>Vulnérabilités: <strong style=\'color:var(--red)\'>' + ST.lastExploit.vulns.length + '</strong></div><button class="btn btn-success" onclick="generateReport()" style="width:100%">✓ Générer et sauvegarder</button>';
  document.getElementById('report-modal').classList.add('open');
}

async function generateReport() {
  if (!ST.lastExploit) return;
  closeModal();
  try {
    var modules = [];
    document.querySelectorAll('#exploit-modules .checkbox-item.checked').forEach(function(l){ modules.push(l.querySelector('input').value); });
    var res = await apiFetch('/api/report/generate', { method:'POST', body: JSON.stringify({ target:ST.lastExploit.target, vulnerabilities:ST.lastExploit.vulns, modules_run:modules }) });
    var data = await res.json();
    if (data.ok) {
      ST.stats.reports++;
      addActivity('📄', 'Rapport '+data.report_id+' généré', 'var(--green)');
      updateDashboard(); loadReportCount();
      showPage('reports', null); loadReports();
      alert('✓ Rapport ' + data.report_id + ' sauvegardé !');
    }
  } catch(e) { alert('Erreur: '+e.message); }
}

async function loadReports() {
  var container = document.getElementById('reports-container');
  try {
    var res = await apiFetch('/api/reports');
    var reports = await res.json();
    if (!reports.length) { container.innerHTML='<div class="alert alert-info">ℹ Aucun rapport — lancez une exploitation pour créer votre premier rapport.</div>'; return; }
    container.innerHTML = reports.map(function(r) {
      return '<div class="report-item"><div class="report-icon">📄</div><div class="report-info"><h4>'+r.id+' — '+r.target+'</h4><p><span class="vuln-badge vuln-critical">'+(r.stats&&r.stats.critical||0)+' CRIT</span> <span class="vuln-badge vuln-high">'+(r.stats&&r.stats.high||0)+' HIGH</span> <span class="vuln-badge vuln-medium">'+(r.stats&&r.stats.medium||0)+' MED</span> <span class="vuln-badge vuln-low">'+(r.stats&&r.stats.low||0)+' LOW</span></p></div><div class="report-meta"><div>'+r.date_display+'</div><div>Expire '+r.expiry+'</div><div style="margin-top:4px;font-size:10px;color:var(--text3)">Par '+r.operator+'</div></div><div style="display:flex;flex-direction:column;gap:4px;min-width:90px"><a class="dl-btn dl-html" href="/api/report/'+r.id+'/html" target="_blank">👁 HTML</a><a class="dl-btn dl-json" href="/api/report/'+r.id+'/json" download>⬇ JSON</a><a class="dl-btn dl-csv" href="/api/report/'+r.id+'/csv" download>⬇ CSV</a><button class="dl-btn" style="border-color:rgba(255,68,68,.3);color:var(--red);background:rgba(255,68,68,.08)" onclick="deleteReport(this.dataset.id)" data-id="'+r.id+'">🗑</button></div></div>';
    }).join('');
  } catch(e) { container.innerHTML='<div class="alert alert-err">✗ Erreur: '+e.message+'</div>'; }
}

async function deleteReport(id) {
  if (!confirm('Supprimer le rapport '+id+' ?')) return;
  await apiFetch('/api/report/'+id, {method:'DELETE'});
  loadReports(); loadReportCount();
}



// ── RBAC ─────────────────────────────────────────────────────────────────────
function applyRBAC(role) {
  // analyst ne peut pas acceder a : users, audit, parametres systeme
  var adminOnly = ['users', 'audit'];
  adminOnly.forEach(function(page) {
    var navItem = document.querySelector('[onclick*="showPage(\'' + page + '\'"]');
    if (navItem) {
      if (role !== 'admin') {
        navItem.style.opacity = '0.4';
        navItem.style.cursor = 'not-allowed';
        navItem.onclick = function() {
          alert('Acces reserve a l administrateur.');
          return false;
        };
      }
    }
  });

  // Masque le bouton de gestion users si analyst
  if (role !== 'admin') {
    var usersNav = document.querySelector('[onclick*="users"]');
    if (usersNav) usersNav.title = 'Admin uniquement';
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
      html += '<div class="report-item" style="margin-bottom:8px">';
      html += '<div style="font-size:18px">' + (isAdmin ? '👑' : '👤') + '</div>';
      html += '<div style="flex:1;font-family:var(--mono);font-size:13px">';
      html += '<strong>' + username + '</strong>';
      html += ' <span class="vuln-badge ' + (isAdmin ? 'vuln-critical' : 'vuln-info') + '">' + role + '</span>';
      html += '</div>';
      html += '<div style="display:flex;gap:8px">';
      html += '<div style="display:flex;gap:8px">';
      html += '<button class="btn btn-warning" style="padding:6px 12px" onclick="promptChangePassword(this.getAttribute(\"data-u\"))" data-u="' + username + '">Changer mdp</button>';
      if (!isAdmin) {
        html += '<button class="btn btn-danger" style="padding:6px 12px" onclick="deleteUser(this.getAttribute(\"data-u\"))" data-u="' + username + '">Supprimer</button>';
      }
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
  if (!confirm('Supprimer l utilisateur ' + username + ' ?')) return;
  try {
    var res = await apiFetch('/api/users/' + username, { method:'DELETE' });
    var data = await res.json();
    if (data.ok) loadUsers();
    else alert(data.error);
  } catch(e) { alert(e.message); }
}

function promptChangePassword(username) {
  var newPass = prompt('Nouveau mot de passe pour ' + username + ' (min 6 caracteres) :');
  if (!newPass) return;
  if (newPass.length < 6) { alert('Trop court (min 6 caracteres)'); return; }
  apiFetch('/api/users/' + username + '/password', { method:'PUT', body: JSON.stringify({password:newPass}) })
    .then(function(res) { return res.json(); })
    .then(function(data) { alert(data.ok ? 'Mot de passe modifie !' : data.error); })
    .catch(function(e) { alert(e.message); });
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
      else if (/NMAP|DNS|ARP|NIKTO|SQLMAP|EXPLOIT/.test(line)) d.className = 't-port';
      else if (/REPORT/.test(line)) d.className = 't-info';
      else d.className = 't-dim';
      t.appendChild(d);
    });
    t.scrollTop = 0;
    addActivity('📋', 'Audit log consulte', 'var(--text2)');
  } catch(e) {
    t.innerHTML = '<span class="t-err">[!] Erreur: ' + e.message + '</span>';
  }
}


// ── GRAPHIQUES DASHBOARD (Canvas pur — pas de dépendance externe) ────────────
var scanKPIs = [];
var vulnData = {crit:0, high:0, med:0, low:0};

function initCharts() {
  // Rien à initialiser, tout est dessiné à la demande
}

function drawDonut(canvasId, crit, high, med, low) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var total = crit + high + med + low;
  var cx = canvas.width / 2, cy = canvas.height / 2, r = 65, ir = 40;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (total === 0) return;

  var slices = [
    {val: crit, color: '#ff4444'},
    {val: high, color: '#ff8c00'},
    {val: med,  color: '#ffd700'},
    {val: low,  color: '#00d4ff'},
  ].filter(function(s) { return s.val > 0; });

  var angle = -Math.PI / 2;
  slices.forEach(function(s) {
    var sweep = (s.val / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle + sweep);
    ctx.closePath();
    ctx.fillStyle = s.color;
    ctx.fill();
    angle += sweep;
  });

  // Trou central
  ctx.beginPath();
  ctx.arc(cx, cy, ir, 0, 2 * Math.PI);
  ctx.fillStyle = '#0f1420';
  ctx.fill();

  // Total au centre
  ctx.fillStyle = '#e8f4ff';
  ctx.font = 'bold 20px JetBrains Mono, monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy);
}

function drawLineChart(canvasId, kpis) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var W = canvas.offsetWidth || 400;
  canvas.width = W;
  var H = 140;
  canvas.height = H;
  ctx.clearRect(0, 0, W, H);

  if (!kpis || kpis.length < 2) {
    ctx.fillStyle = '#3d5a7a';
    ctx.font = '12px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Lancez au moins 2 scans pour voir la courbe', W/2, H/2);
    return;
  }

  var pts = kpis.slice(0, 10).reverse();
  var pad = {l:30, r:10, t:10, b:30};
  var cW = W - pad.l - pad.r;
  var cH = H - pad.t - pad.b;

  // Grille
  ctx.strokeStyle = '#1e2d4a';
  ctx.lineWidth = 0.5;
  for (var g = 0; g <= 4; g++) {
    var gy = pad.t + (g / 4) * cH;
    ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke();
  }

  // Ligne
  ctx.strokeStyle = '#00d4ff';
  ctx.lineWidth = 2;
  ctx.shadowColor = '#00d4ff';
  ctx.shadowBlur = 6;
  ctx.beginPath();
  pts.forEach(function(p, i) {
    var x = pad.l + (i / (pts.length - 1)) * cW;
    var y = pad.t + cH - ((i + 1) / pts.length) * cH * 0.8;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Zone remplie
  ctx.fillStyle = 'rgba(0,212,255,0.07)';
  ctx.beginPath();
  pts.forEach(function(p, i) {
    var x = pad.l + (i / (pts.length - 1)) * cW;
    var y = pad.t + cH - ((i + 1) / pts.length) * cH * 0.8;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.lineTo(pad.l + cW, pad.t + cH);
  ctx.lineTo(pad.l, pad.t + cH);
  ctx.closePath();
  ctx.fill();

  // Points
  pts.forEach(function(p, i) {
    var x = pad.l + (i / (pts.length - 1)) * cW;
    var y = pad.t + cH - ((i + 1) / pts.length) * cH * 0.8;
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, 2 * Math.PI);
    ctx.fillStyle = '#00d4ff';
    ctx.fill();
  });

  // Labels X
  ctx.fillStyle = '#3d5a7a';
  ctx.font = '9px JetBrains Mono, monospace';
  ctx.textAlign = 'center';
  pts.forEach(function(p, i) {
    var x = pad.l + (i / (pts.length - 1)) * cW;
    var label = p.time || '';
    ctx.fillText(label.substring(0,5), x, H - 8);
  });
}

function updateVulnChart(crit, high, med, low) {
  vulnData = {crit:crit, high:high, med:med, low:low};
  var total = crit + high + med + low;
  var noMsg = document.getElementById('no-vulns-msg');
  var canvas = document.getElementById('vuln-chart');
  if (total === 0) {
    if (noMsg) noMsg.style.display = 'block';
    if (canvas) canvas.style.display = 'none';
    return;
  }
  if (noMsg) noMsg.style.display = 'none';
  if (canvas) canvas.style.display = 'block';
  document.getElementById('leg-crit').textContent = crit;
  document.getElementById('leg-high').textContent = high;
  document.getElementById('leg-med').textContent = med;
  document.getElementById('leg-low').textContent = low;
  drawDonut('vuln-chart', crit, high, med, low);
}

function addScanKPI(action, target, elapsed) {
  scanKPIs.unshift({action:action, target:target, elapsed:elapsed, time:new Date().toLocaleTimeString('fr-FR')});
  if (scanKPIs.length > 20) scanKPIs.pop();
  renderKPITable();
  var noMsg = document.getElementById('no-activity-msg');
  var canvas = document.getElementById('activity-chart');
  if (noMsg) noMsg.style.display = 'none';
  if (canvas) canvas.style.display = 'block';
  setTimeout(function() { drawLineChart('activity-chart', scanKPIs); }, 50);
}

function renderKPITable() {
  var el = document.getElementById('kpi-table');
  if (!el || !scanKPIs.length) return;
  var rows = scanKPIs.map(function(k) {
    var color = k.elapsed > 60 ? 'var(--orange)' : k.elapsed > 10 ? 'var(--yellow)' : 'var(--green)';
    return '<tr>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:11px;color:var(--text3)">' + k.time + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:11px;color:var(--accent)">' + k.action + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:12px">' + k.target + '</td>' +
      '<td style="padding:7px 10px;font-family:var(--mono);font-size:12px;color:' + color + ';font-weight:700">' + k.elapsed + 's</td>' +
      '</tr>';
  }).join('');
  el.innerHTML = '<table class="result-table" style="width:100%">' +
    '<thead><tr><th>Heure</th><th>Module</th><th>Cible</th><th>Durée</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>';
}

// ── HYDRA ─────────────────────────────────────────────────────────────────────
async function runHydra() {
  var target   = document.getElementById('hydra-target').value.trim();
  var service  = document.getElementById('hydra-service').value;
  var username = document.getElementById('hydra-username').value.trim() || 'admin';
  var wordlist = document.getElementById('hydra-wordlist').value;
  if (!target) return alert('Entrez une cible.');
  var btn = document.getElementById('hydra-btn');
  btn.disabled = true;
  var stop = progressStart('hydra-pb','hydra-fill',30000);
  termSet('hydra-out', '[*] Hydra → ' + target + ' (' + service + ')\n[*] User: ' + username + '\n[*] En cours...');
  try {
    var res = await apiFetch('/api/hydra', {
      method:'POST',
      body: JSON.stringify({target:target, service:service, username:username, wordlist:wordlist})
    });
    var data = await res.json();
    if (data.error) {
      termSet('hydra-out', '[!] ' + data.error + (data.install ? '\nInstall: ' + data.install : ''));
    } else {
      termSet('hydra-out', data.output);
      if (data.elapsed) addScanKPI('HYDRA', target, data.elapsed);
    }
    ST.stats.scans++;
    addActivity('🔑', 'Hydra → ' + target + ' (' + service + ')', 'var(--red)');
    updateDashboard();
  } catch(e) { termSet('hydra-out', '[!] ' + e.message); }
  stop(); btn.disabled = false;
}

function closeModal() { document.getElementById('report-modal').classList.remove('open'); }
document.getElementById('report-modal').addEventListener('click', function(e){ if(e.target===this) closeModal(); });
document.addEventListener('keydown', function(e) { if(e.key==='Escape') closeModal(); });
