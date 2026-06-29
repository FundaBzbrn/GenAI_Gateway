/*
 * GenAI Security Gateway - Frontend Uygulaması (app.js)
 *
 * Bu JavaScript dosyası, kullanıcıların sisteme giriş yaptığı, prompt gönderdiği
 * ve güvenlik analiz sonuçlarını gördüğü web arayüzünün mantığını (logic) yönetir.
 * 
 * Ana İşlevler:
 * 1. Sunucu ile haberleşme (Fetch API ile REST çağrıları)
 * 2. JWT (JSON Web Token) yönetimi ve LocalStorage'da saklanması
 * 3. Arayüz etkileşimleri (Buton tıklamaları, modal açılıp kapanması)
 * 4. Animasyonlar ve bildirim (toast) mesajları
 */

const API_BASE = '/api/v1';

const notifiedLogs = new Set();

function showToast(title, message, logData) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  toast.innerHTML = `
    <div class="toast-icon">
      <i data-lucide="bell-ring" style="width:20px;height:20px;"></i>
    </div>
    <div class="toast-content">
      <div class="toast-title">${title}</div>
      <div class="toast-body">${message}</div>
    </div>
  `;

  toast.onclick = () => {
    openLogModal(logData);
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  };

  container.appendChild(toast);
  
  if (window.lucide) {
    lucide.createIcons();
  }

  setTimeout(() => {
    toast.classList.add('show');
  }, 50);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }
  }, 6000);
}

async function apiFetch(path, opts = {}) {
  const token = localStorage.getItem('token');
  if (!opts.headers) opts.headers = {};
  if (token) {
    opts.headers['Authorization'] = `Bearer ${token}`;
  }
  
  try {
    const res = await fetch(path, opts);
    if (res.status === 401 || res.status === 403) {
      if (!path.includes('/login')) {
        localStorage.removeItem('token');
        localStorage.removeItem('role');
        window.location.href = '/login.html';
      }
    }
    return res;
  } catch (e) {
    console.error('Network error:', e, path);
    return null;
  }
}

const refs = {
  navDashboard: document.getElementById('nav-dashboard'),
  navLogs: document.getElementById('nav-logs'),
  navUsers: document.getElementById('nav-users'),
  navProfiles: document.getElementById('nav-profiles'),
  navSettings: document.getElementById('nav-settings'),
  viewDashboard: document.getElementById('view-dashboard'),
  viewLogs: document.getElementById('view-logs'),
  viewUsers: document.getElementById('view-users'),
  viewProfiles: document.getElementById('view-profiles'),
  viewSettings: document.getElementById('view-settings'),
  valTotal: document.getElementById('valTotal'),
  valBlocked: document.getElementById('valBlocked'),
  valAllowed: document.getElementById('valAllowed'),
  valLatency: document.getElementById('valLatency'),
  logsTableBody: document.getElementById('logsTableBody'),
  fullLogsTableBody: document.getElementById('fullLogsTableBody'),
  ratioChart: document.getElementById('ratioChart'),
  categoryChart: document.getElementById('categoryChart'),
  refreshBtn: document.getElementById('refreshBtn'),
  logDetailModal: document.getElementById('logDetailModal'),
  closeModalBtn: document.getElementById('closeModalBtn'),
  modalTitle: document.getElementById('modalLogIdTitle'),
  mdlDate: document.getElementById('mdlDate'),
  mdlTime: document.getElementById('mdlTime'),
  mdlUser: document.getElementById('mdlUser'),
  mdlStatus: document.getElementById('mdlStatus'),
  mdlBypassStatus: document.getElementById('mdlBypassStatus'),
  mdlJustification: document.getElementById('mdlJustification'),
  mdlPrompt: document.getElementById('mdlPrompt'),
  mdlWarning: document.getElementById('mdlWarning'),
  mdlLayer: document.getElementById('mdlLayer'),
  mdlScoreBar: document.getElementById('mdlScoreBar'),
  mdlScoreText: document.getElementById('mdlScoreText'),
  mdlCategory: document.getElementById('mdlCategory'),
  btnValidate: document.getElementById('btnValidate'),
  btnFalsePositive: document.getElementById('btnFalsePositive'),
  modalStandardFooter: document.getElementById('modalStandardFooter'),
  modalApprovalFooter: document.getElementById('modalApprovalFooter'),
  btnApproveRequest: document.getElementById('btnApproveRequest'),
  btnRejectRequest: document.getElementById('btnRejectRequest'),
  t1: document.getElementById('tglLayer1'),
  t2: document.getElementById('tglLayer2'),
  t3: document.getElementById('tglLayer3'),
  stsL1: document.getElementById('stsL1'),
  stsL2: document.getElementById('stsL2'),
  stsL3: document.getElementById('stsL3'),
  aiRange: document.getElementById('aiThreshold'),
  aiVal: document.getElementById('aiThresholdVal'),
  blacklistWrapper: document.getElementById('blacklistTags'),
  blacklistInput: document.getElementById('blacklistInput'),
  addWordBtn: document.getElementById('addWordBtn'),
  saveRulesBtn: document.getElementById('saveRulesBtn')
};

let charts = { ratio: null, category: null };

function extractDate(iso) {
  const date = new Date(iso);
  return {
    date: date.toLocaleDateString('tr-TR'),
    time: date.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  };
}

function safeEncode(obj) {
  return btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
}

function safeDecode(str) {
  return JSON.parse(decodeURIComponent(escape(atob(str))));
}

function updateLayerStatus() {
  refs.stsL1.innerText = refs.t1.checked ? '✅ Aktif' : '❌ Pasif';
  refs.stsL2.innerText = refs.t2.checked ? '✅ Aktif' : '❌ Pasif';
  refs.stsL3.innerText = refs.t3.checked ? '✅ Aktif' : '❌ Pasif';
}

async function openLogModal(data) {
  const log = typeof data === 'string' ? safeDecode(data) : data;
  const dt = extractDate(log.created_at || new Date().toISOString());
  refs.modalTitle.innerText = `Log Detayı: #${(log.log_id || '').split('-')[0]}`;
  refs.mdlDate.innerText = dt.date;
  refs.mdlTime.innerText = dt.time;
  refs.mdlUser.innerText = log.user_id || '-';
  refs.mdlPrompt.innerText = log.masked_prompt || '-';
  refs.mdlLayer.innerText = log.stopped_at_layer || '-';
  refs.mdlCategory.innerText = log.category || '-';
  
  if (refs.mdlBypassStatus) refs.mdlBypassStatus.innerText = log.bypass_status || 'Yok';
  if (refs.mdlJustification) refs.mdlJustification.innerText = log.justification || 'Gerekçe belirtilmedi';
  
  const pct = Math.round((log.ai_confidence_score || 0) * 100);
  refs.mdlScoreText.innerText = pct;
  refs.mdlScoreBar.style.width = pct + '%';
  
  // Reset custom styles if any
  refs.mdlStatus.style.background = '';
  refs.mdlStatus.style.color = '';
  
  if (log.action === 'BLOCK') {
    refs.mdlStatus.innerText = 'BLOKLANDI';
    refs.mdlStatus.className = 'badge badge-lg badge-block';
    refs.mdlWarning.style.display = 'flex';
  } else if (log.action === 'PENDING') {
    refs.mdlStatus.innerText = 'ONAY BEKLİYOR';
    refs.mdlStatus.className = 'badge badge-lg';
    refs.mdlStatus.style.background = '#f59e0b';
    refs.mdlStatus.style.color = 'white';
    refs.mdlWarning.style.display = 'flex';
  } else {
    refs.mdlStatus.innerText = 'İZİN VERİLDİ';
    refs.mdlStatus.className = 'badge badge-lg badge-allow';
    refs.mdlWarning.style.display = 'none';
  }

  // Handle footer visibility for approvals
  if (log.action === 'PENDING') {
    if (refs.modalStandardFooter) refs.modalStandardFooter.style.display = 'none';
    if (refs.modalApprovalFooter) refs.modalApprovalFooter.style.display = 'flex';
    
    if (refs.btnApproveRequest) {
      refs.btnApproveRequest.disabled = false;
      refs.btnApproveRequest.innerHTML = 'Talebi Onayla (ALLOW) <i data-lucide="check" style="width:18px;"></i>';
      refs.btnApproveRequest.onclick = () => handleManagerDecision(log.log_id, 'approve', refs.btnApproveRequest);
    }
    if (refs.btnRejectRequest) {
      refs.btnRejectRequest.disabled = false;
      refs.btnRejectRequest.innerHTML = 'Talebi Reddet (BLOCK) <i data-lucide="x" style="width:18px;"></i>';
      refs.btnRejectRequest.onclick = () => handleManagerDecision(log.log_id, 'reject', refs.btnRejectRequest);
    }
  } else {
    if (refs.modalStandardFooter) refs.modalStandardFooter.style.display = 'flex';
    if (refs.modalApprovalFooter) refs.modalApprovalFooter.style.display = 'none';
  }
  
  refs.btnValidate.onclick = () => submitFeedback(log.log_id, 'safe', refs.btnValidate);
  refs.btnFalsePositive.onclick = () => submitFeedback(log.log_id, 'false_positive', refs.btnFalsePositive);
  refs.logDetailModal.style.display = 'flex';
  if (window.lucide) lucide.createIcons();
}

function closeLogModal() {
  refs.logDetailModal.style.display = 'none';
}

async function handleManagerDecision(logId, decision, btn) {
  const original = btn.innerHTML;
  btn.innerHTML = decision === 'approve' ? 'Onaylanıyor...' : 'Reddediliyor...';
  btn.disabled = true;
  try {
    const res = await apiFetch(`${API_BASE}/admin/company/logs/${encodeURIComponent(logId)}/${decision}`, { 
      method: 'POST' 
    });
    if (!res || !res.ok) throw new Error('Action failed');
    btn.innerHTML = decision === 'approve' ? 'Onaylandı' : 'Reddedildi';
    setTimeout(() => {
      closeLogModal();
      refreshDashboard();
      if (window.location.hash === '#nav-logs' || refs.viewLogs.classList.contains('active')) {
        fetchDetailedLogs();
      }
    }, 1200);
  } catch (error) {
    console.error(error);
    btn.innerHTML = 'Hata';
    setTimeout(() => { 
      btn.innerHTML = original; 
      btn.disabled = false;
    }, 1500);
  }
}

async function submitFeedback(logId, type, btn) {
  const original = btn.innerHTML;
  btn.innerHTML = 'Kaydediliyor...';
  try {
    const res = await apiFetch(`${API_BASE}/feedback?log_id=${encodeURIComponent(logId)}&feedback_type=${encodeURIComponent(type)}`, { method: 'POST' });
    if (!res || !res.ok) throw new Error('Feedback failed');
    btn.innerHTML = 'Teşekkürler';
    setTimeout(closeLogModal, 1200);
  } catch (error) {
    console.error(error);
    btn.innerHTML = 'Hata';
    setTimeout(() => { btn.innerHTML = original; }, 1500);
  }
}

async function initCharts() {
  if (!refs.ratioChart || !refs.categoryChart) return;

  Chart.defaults.font.family = "'Outfit', sans-serif";
  Chart.defaults.color = '#7C7A88';

  // ── Doughnut: Karar Dağılımı ──
  const dCtx = refs.ratioChart.getContext('2d');
  charts.ratio = new Chart(dCtx, {
    type: 'doughnut',
    data: {
      labels: ['Engellenen', 'İzin Verilen'],
      datasets: [{
        data: [0, 0],
        backgroundColor: ['#EF4444', '#10B981'],
        hoverBackgroundColor: ['#F87171', '#34D399'],
        borderWidth: 0,
        hoverOffset: 10,
        spacing: 2
      }]
    },
    options: {
      cutout: '72%',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            padding: 20,
            font: { family: "'Outfit', sans-serif", size: 12, weight: '600' },
            usePointStyle: true,
            pointStyleWidth: 10
          }
        },
        tooltip: {
          backgroundColor: 'rgba(19,17,28,0.95)',
          borderColor: 'rgba(157,110,248,0.25)',
          borderWidth: 1,
          padding: 12,
          titleFont: { family: "'Outfit'", size: 13, weight: '700' },
          bodyFont:  { family: "'Outfit'", size: 12 },
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.raw} istek`
          }
        }
      },
      animation: { animateRotate: true, duration: 900, easing: 'easeInOutQuart' }
    }
  });

  // ── Bar: Güvenlik Olayları Kategorileri ──
  const bCtx = refs.categoryChart.getContext('2d');

  // Gradient fill for bars
  const gradBar = bCtx.createLinearGradient(0, 0, 0, 260);
  gradBar.addColorStop(0,   'rgba(157,110,248,0.95)');
  gradBar.addColorStop(1,   'rgba(99,102,241,0.35)');

  charts.category = new Chart(bCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Olay Sayısı',
        data: [],
        backgroundColor: gradBar,
        borderColor: 'rgba(157,110,248,0.6)',
        borderWidth: 1,
        borderRadius: 8,
        borderSkipped: false,
        hoverBackgroundColor: 'rgba(196,181,253,0.85)'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            font: { family: "'Outfit'", size: 12, weight: '600' },
            usePointStyle: true,
            pointStyleWidth: 8
          }
        },
        tooltip: {
          backgroundColor: 'rgba(19,17,28,0.95)',
          borderColor: 'rgba(157,110,248,0.25)',
          borderWidth: 1,
          padding: 12,
          titleFont: { family: "'Outfit'", size: 13, weight: '700' },
          bodyFont:  { family: "'Outfit'", size: 12 },
          callbacks: {
            label: ctx => ` ${ctx.raw} olay`
          }
        }
      },
      scales: {
        x: {
          grid: { display: false },
          border: { display: false },
          ticks: { font: { family: "'Outfit'", size: 11, weight: '600' } }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(255,255,255,0.05)',
            drawBorder: false
          },
          border: { display: false, dash: [4,4] },
          ticks: { font: { family: "'Outfit'", size: 11 }, precision: 0 }
        }
      },
      animation: { duration: 900, easing: 'easeInOutQuart' }
    }
  });
}

async function refreshDashboard() {
  const role = localStorage.getItem('role');
  let statsPath = `${API_BASE}/stats`;
  let logsPath = `${API_BASE}/logs?limit=10`;
  
  if (role === 'company_admin') {
      statsPath = `${API_BASE}/admin/company/stats`;
      logsPath = `${API_BASE}/admin/company/logs?limit=10`;
  } else if (role !== 'super_admin') {
      statsPath = `${API_BASE}/user/stats`;
      logsPath = `${API_BASE}/user/logs?limit=10`;
  }

  const statsRes = await apiFetch(statsPath);
  if (!statsRes) return;
  const stats = await statsRes.json();
  refs.valTotal.innerText = stats.total_requests || 0;
  refs.valBlocked.innerText = stats.blocked || 0;
  refs.valAllowed.innerText = stats.allowed || 0;
  refs.valLatency.innerText = `${stats.avg_latency_ms || 0}ms`;
  if (charts.ratio) {
    charts.ratio.data.datasets[0].data = [stats.blocked || 0, stats.allowed || 0];
    charts.ratio.update();
  }
  const logsRes = await apiFetch(logsPath);
  if (!logsRes) return;
  const logs = await logsRes.json();
  let html = '';
  if (logs.logs && logs.logs.length) {
    logs.logs.forEach(log => {
      const dt = extractDate(log.created_at || new Date().toISOString());
      html += `<tr style="cursor:pointer;" onclick='openLogModal("${safeEncode(log)}")'>
        <td>${dt.time}</td>
        <td>${log.user_id || '-'}</td>
        <td>${(log.masked_prompt || '-').slice(0, 80)}</td>
        <td>${log.stopped_at_layer || '-'}</td>
        <td>${log.category || '-'}</td>
        <td>${log.action || '-'}</td>
      </tr>`;
    });
  } else {
    html = '<tr><td colspan="6" class="text-center">Henüz kayıt yok.</td></tr>';
  }
  refs.logsTableBody.innerHTML = html;
  if (charts.category) {
    const counts = {};
    (logs.logs || []).forEach(log => { counts[log.category] = (counts[log.category] || 0) + 1; });
    charts.category.data.labels = Object.keys(counts);
    charts.category.data.datasets[0].data = Object.values(counts);
    charts.category.update();
  }

  // Yöneticiler için onay bekleyen yeni taleplerin bildirimini göster
  if (role === 'company_admin' || role === 'super_admin') {
    (logs.logs || []).forEach(log => {
      if (log.action === 'PENDING' && !notifiedLogs.has(log.log_id)) {
        notifiedLogs.add(log.log_id);
        showToast(
          "Yeni Onay Talebi 📨",
          `<b>${log.user_id}</b> kullanıcısı onay bekleyen bir işlem gerçekleştirdi.<br>Gerekçe: <i>${log.justification || 'Girilmedi'}</i>`,
          log
        );
      }
    });
  }
}

function buildFilterUrl() {
  const role = localStorage.getItem('role');
  let url = role === 'company_admin' ? `${API_BASE}/admin/company/logs?limit=200` : `${API_BASE}/logs?limit=200`;
  if (role !== 'company_admin' && role !== 'super_admin') {
      url = `${API_BASE}/user/logs?limit=200`;
  }
  if (window._actionFilter) url += `&action=${window._actionFilter}`;
  if (window._categoryFilter) url += `&category=${window._categoryFilter}`;
  return url;
}

async function fetchDetailedLogs() {
  refs.fullLogsTableBody.innerHTML = '<tr><td colspan="6" class="text-center">Yükleniyor...</td></tr>';
  const res = await apiFetch(buildFilterUrl());
  if (!res) return;
  const data = await res.json();
  let html = '';
  if (data.logs && data.logs.length) {
    data.logs.forEach(log => {
      const dt = extractDate(log.created_at || new Date().toISOString());
      html += `<tr style="cursor:pointer;" onclick='openLogModal("${safeEncode(log)}")'>
        <td>${(log.log_id || '').split('-')[0]}</td>
        <td>${dt.date} ${dt.time}</td>
        <td>${log.user_id || '-'}</td>
        <td>${log.stopped_at_layer || '-'}</td>
        <td>${log.category || '-'}</td>
        <td>${log.action || '-'}</td>
      </tr>`;
    });
  } else {
    html = '<tr><td colspan="6" class="text-center">Kayıt bulunamadı.</td></tr>';
  }
  refs.fullLogsTableBody.innerHTML = html;
}

function renderBlacklist(words) {
  refs.blacklistWrapper.innerHTML = '';
  (words || []).forEach(word => {
    const tag = document.createElement('div');
    tag.className = 'blacklist-tag';
    tag.innerHTML = `${word} <button class="tag-remove">✕</button>`;
    tag.querySelector('.tag-remove').onclick = () => removeBlacklist(word);
    refs.blacklistWrapper.appendChild(tag);
  });
}

async function fetchRules() {
  const res = await apiFetch(`${API_BASE}/config`);
  if (!res) return;
  const cfg = await res.json();
  refs.t1.checked = !!cfg.layer_regex;
  refs.t2.checked = !!cfg.layer_deberta;
  refs.t3.checked = !!cfg.layer_llm;
  refs.stsL1.innerText = cfg.layer_regex ? '[ON]' : '[OFF]';
  refs.stsL2.innerText = cfg.layer_deberta ? '[ON]' : '[OFF]';
  refs.stsL3.innerText = cfg.layer_llm ? '[ON]' : '[OFF]';
  refs.aiRange.value = cfg.ai_threshold || 0.75;
  refs.aiVal.innerText = refs.aiRange.value;
  renderBlacklist(cfg.blacklist || []);
}

async function addBlacklist() {
  const word = refs.blacklistInput.value.trim();
  if (!word) return alert('Kelime girin');
  const res = await apiFetch(`${API_BASE}/config/blacklist?operation=add&word=${encodeURIComponent(word)}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Kelime eklenemedi');
  const data = await res.json();
  renderBlacklist(data.blacklist || []);
  refs.blacklistInput.value = '';
}

async function removeBlacklist(word) {
  if (!confirm(`"${word}" silinsin mi?`)) return;
  const res = await apiFetch(`${API_BASE}/config/blacklist?operation=remove&word=${encodeURIComponent(word)}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Kelime silinemedi');
  const data = await res.json();
  renderBlacklist(data.blacklist || []);
}

async function saveThreshold() {
  const value = parseFloat(refs.aiRange.value);
  const res = await apiFetch(`${API_BASE}/config/threshold?threshold=${value}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Threshold kaydedilemedi');
  alert('Threshold kaydedildi');
}

async function toggleLayer(n) {
  const params = new URLSearchParams();
  if (n === 1) params.append('layer1', refs.t1.checked);
  if (n === 2) params.append('layer2', refs.t2.checked);
  if (n === 3) params.append('layer3', refs.t3.checked);
  const res = await apiFetch(`${API_BASE}/config/layers?${params.toString()}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Layer güncellenemedi');
  fetchRules();
}

window.addEventListener('DOMContentLoaded', async () => {
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const userProfileIcon = document.getElementById('userProfileIcon');

  // Token geçerliliğini backend'den doğrula
  async function verifyToken() {
    if (!token) return false;
    try {
      const res = await fetch(`${API_BASE}/stats`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return res.status !== 401 && res.status !== 403;
    } catch {
      return false;
    }
  }

  const isValid = await verifyToken();

  if (isValid) {
    if (logoutBtn) logoutBtn.style.display = 'flex';
    if (userProfileIcon) {
        userProfileIcon.style.display = 'flex';
        const fullName = localStorage.getItem('full_name');
        const username = localStorage.getItem('username');
        let initials = 'US';
        if (fullName && fullName.trim().length > 0) {
            const parts = fullName.trim().split(' ').filter(p => p.length > 0);
            if (parts.length >= 2) {
                initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
            } else if (parts.length === 1) {
                initials = parts[0].substring(0, 2).toUpperCase();
            }
        } else if (username && username.trim().length > 0) {
            initials = username.substring(0, 2).toUpperCase();
        }
        userProfileIcon.innerHTML = initials;
    }
    if (loginBtn) loginBtn.style.display = 'none';
  } else {
    // Token yok veya geçersiz - temizle
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    window.location.href = '/login.html'; // Force redirect to login page
    if (loginBtn) loginBtn.style.display = 'flex';
    if (logoutBtn) logoutBtn.style.display = 'none';
    if (userProfileIcon) userProfileIcon.style.display = 'none';
  }

  if (loginBtn) {
      loginBtn.addEventListener('click', () => {
          window.location.href = '/login.html';
      });
  }

  if (role === 'company_admin') {
      if (refs.navUsers) refs.navUsers.style.display = 'flex';
      if (refs.navProfiles) refs.navProfiles.style.display = 'flex';
      if (refs.navSettings) refs.navSettings.style.display = 'flex'; // company_admin görebilir
      const h1 = document.querySelector('.header-titles h1');
      if (h1) h1.innerText = 'Yönetici Paneli';
      const sub = document.querySelector('.header-titles .subtitle');
      if (sub) sub.innerText = 'Gerçek zamanlı tehdit ve sızıntı tespit analizi';
  } else {
      // employee veya diğer roller - Güvenlik Kuralları gizli
      if (refs.navSettings) refs.navSettings.style.display = 'none';
      // Çalışan başlığı
      const h1 = document.querySelector('.header-titles h1');
      if (h1) h1.innerText = 'Çalışan Paneli';
      const sub = document.querySelector('.header-titles .subtitle');
      if (sub) sub.innerText = 'Güvenli yapay zeka erişimi ve geçmiş kayıtlarınız';
  }

  function switchTab(navEl, viewEl, callback) {
    refs.navDashboard.classList.remove('active');
    refs.navLogs.classList.remove('active');
    if (refs.navUsers) refs.navUsers.classList.remove('active');
    if (refs.navProfiles) refs.navProfiles.classList.remove('active');
    if (refs.navSettings) refs.navSettings.classList.remove('active');
    navEl.classList.add('active');

    refs.viewDashboard.classList.remove('active');
    refs.viewLogs.classList.remove('active');
    if (refs.viewUsers) refs.viewUsers.classList.remove('active');
    if (refs.viewProfiles) refs.viewProfiles.classList.remove('active');
    if (refs.viewSettings) refs.viewSettings.classList.remove('active');
    viewEl.classList.add('active');

    const mainContent = document.querySelector('.main-content');
    if (mainContent) mainContent.scrollTo(0, 0); // Sayfanın en üstüne kaydır
    if (callback) callback();
    // Yarı-Canlı Mod aktifse sekme değişimini bildir
    if (typeof window._onTabSwitch === 'function') {
      setTimeout(window._onTabSwitch, 50); // view class'ı eklendikten sonra çalıştır
    }
  }

  refs.navDashboard.addEventListener('click', e => { e.preventDefault(); switchTab(refs.navDashboard, refs.viewDashboard, refreshDashboard); });
  refs.navLogs.addEventListener('click', e => { e.preventDefault(); switchTab(refs.navLogs, refs.viewLogs, fetchDetailedLogs); });
  if (refs.navUsers) refs.navUsers.addEventListener('click', e => { e.preventDefault(); switchTab(refs.navUsers, refs.viewUsers); });
  if (refs.navProfiles) refs.navProfiles.addEventListener('click', e => { e.preventDefault(); switchTab(refs.navProfiles, refs.viewProfiles, fetchProfiles); });
  if (refs.navSettings) refs.navSettings.addEventListener('click', e => { e.preventDefault(); switchTab(refs.navSettings, refs.viewSettings, fetchRules); });

  document.querySelectorAll('.filter-pill[data-action]').forEach(pill => pill.addEventListener('click', () => { window._actionFilter = pill.dataset.action; fetchDetailedLogs(); }));
  document.querySelectorAll('.filter-pill[data-category]').forEach(pill => pill.addEventListener('click', () => { window._categoryFilter = pill.dataset.category; fetchDetailedLogs(); }));

  refs.closeModalBtn.addEventListener('click', closeLogModal);
  refs.logDetailModal.addEventListener('click', e => { if (e.target === refs.logDetailModal) closeLogModal(); });
  if (refs.addWordBtn) refs.addWordBtn.addEventListener('click', addBlacklist);
  if (refs.blacklistInput) refs.blacklistInput.addEventListener('keypress', e => { if (e.key === 'Enter') addBlacklist(); });
  if (refs.saveRulesBtn) refs.saveRulesBtn.addEventListener('click', saveThreshold);
  if (refs.t1) refs.t1.addEventListener('change', () => { updateLayerStatus(); toggleLayer(1); });
  if (refs.t2) refs.t2.addEventListener('change', () => { updateLayerStatus(); toggleLayer(2); });
  if (refs.t3) refs.t3.addEventListener('change', () => { updateLayerStatus(); toggleLayer(3); });
  if (refs.aiRange) refs.aiRange.addEventListener('input', () => { if (refs.aiVal) refs.aiVal.innerText = refs.aiRange.value; });
  // ══════════════════════════════════════════════════════
  //  YARI-CANLI MOD — Tam işlevli otomatik yenileme sistemi
  // ══════════════════════════════════════════════════════
  const LIVE_INTERVAL_MS = 10000; // 10 saniye
  let _liveCountdown   = LIVE_INTERVAL_MS / 1000;
  let _liveTimer       = null; // setInterval ID (ana yenileme)
  let _liveCountTick   = null; // setInterval ID (geri sayım)
  let _lastRefreshTime = null;

  // Şu an aktif olan sekmeyi döndürür
  function getActiveView() {
    if (refs.viewLogs     && refs.viewLogs.classList.contains('active'))     return 'logs';
    if (refs.viewUsers    && refs.viewUsers.classList.contains('active'))    return 'users';
    if (refs.viewProfiles && refs.viewProfiles.classList.contains('active')) return 'profiles';
    if (refs.viewSettings && refs.viewSettings.classList.contains('active')) return 'settings';
    return 'dashboard'; // varsayılan
  }

  // Aktif sekmeye göre uygun yenileme fonksiyonunu çağırır
  async function liveRefreshActiveView() {
    const view = getActiveView();
    switch(view) {
      case 'dashboard': await refreshDashboard(); break;
      case 'logs':      await fetchDetailedLogs(); break;
      // Diğer sekmeler için dashboard istatistiklerini arka planda güncelle
      case 'users':
      case 'profiles':
      case 'settings':  await refreshDashboard(); break;
    }
    _lastRefreshTime = new Date();
    updateLiveStatus();
  }

  // Buton metnini ve geri sayım göstergesini günceller
  function updateLiveStatus() {
    if (!refs.refreshBtn) return;
    const isActive = !!_liveTimer;
    if (isActive) {
      const secText = _liveCountdown <= 0 ? '⟳' : `${_liveCountdown}s`;
      refs.refreshBtn.querySelector('span').innerText = `Canlı: ${secText}`;
    } else {
      refs.refreshBtn.querySelector('span').innerText = 'Yarı-Canlı Mod';
    }
  }

  // Yarı-Canlı Modu BAŞLAT
  function startLiveMode() {
    refs.refreshBtn.classList.add('active-refresh');
    _liveCountdown = LIVE_INTERVAL_MS / 1000;

    // Hemen bir kez yenile
    liveRefreshActiveView();

    // Geri sayım tick (her saniye)
    _liveCountTick = setInterval(() => {
      _liveCountdown--;
      if (_liveCountdown < 0) _liveCountdown = LIVE_INTERVAL_MS / 1000;
      updateLiveStatus();
    }, 1000);

    // Ana yenileme timer
    _liveTimer = setInterval(() => {
      _liveCountdown = LIVE_INTERVAL_MS / 1000;
      liveRefreshActiveView();
    }, LIVE_INTERVAL_MS);

    // Başlangıç durumu göster
    updateLiveStatus();

    // Sidebar'daki status indicator'ı da güncelle
    const statusEl = document.querySelector('.status-indicator');
    if (statusEl) {
      statusEl.innerHTML = `<span class="pulse pulse-live"></span> Canlı İzleme Aktif`;
    }
  }

  // Yarı-Canlı Modu DURDUR
  function stopLiveMode() {
    clearInterval(_liveTimer);
    clearInterval(_liveCountTick);
    _liveTimer = null;
    _liveCountTick = null;
    _liveCountdown = LIVE_INTERVAL_MS / 1000;
    refs.refreshBtn.classList.remove('active-refresh');
    updateLiveStatus();

    // Sidebar'ı eski haline döndür
    const statusEl = document.querySelector('.status-indicator');
    if (statusEl) {
      statusEl.innerHTML = `<span class="pulse"></span> Sistem Aktif`;
    }
  }

  // Sekme değiştiğinde aktif moda göre doğru veriyi çek
  // (switchTab fonksiyonunun ardından çağrılacak)
  window._onTabSwitch = function() {
    if (_liveTimer) {
      // Sekme değişti, hemen yeni sekmenin verisini çek
      _liveCountdown = LIVE_INTERVAL_MS / 1000;
      clearInterval(_liveTimer);
      clearInterval(_liveCountTick);

      liveRefreshActiveView();

      _liveCountTick = setInterval(() => {
        _liveCountdown--;
        if (_liveCountdown < 0) _liveCountdown = LIVE_INTERVAL_MS / 1000;
        updateLiveStatus();
      }, 1000);
      _liveTimer = setInterval(() => {
        _liveCountdown = LIVE_INTERVAL_MS / 1000;
        liveRefreshActiveView();
      }, LIVE_INTERVAL_MS);
    }
  };

  refs.refreshBtn.addEventListener('click', () => {
    if (_liveTimer) {
      stopLiveMode();
    } else {
      startLiveMode();
    }
  });
  
  if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
          localStorage.removeItem('token');
          localStorage.removeItem('role');
          window.location.href = '/login.html';
      });
  }

  const addEmployeeForm = document.getElementById('addEmployeeForm');
  if (addEmployeeForm) {
      addEmployeeForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const username = document.getElementById('empUsername').value;
          const password = document.getElementById('empPassword').value;
          const email = document.getElementById('empEmail').value;
          const department = document.getElementById('empDepartment') ? document.getElementById('empDepartment').value : '';
          const full_name = document.getElementById('empFullName') ? document.getElementById('empFullName').value : '';
          
          try {
              const res = await apiFetch(`${API_BASE}/admin/company/employees`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ username, password, email, department, full_name })
              });
              
              if (res && res.ok) {
                  alert('Çalışan başarıyla eklendi!');
                  addEmployeeForm.reset();
              } else {
                  const data = await res.json();
                  alert('Hata: ' + (data.detail || 'Bilinmeyen hata'));
              }
          } catch(err) {
              alert('Bir hata oluştu.');
          }
      });
  }

  const themeToggleBtn = document.getElementById('themeToggleBtn');
  if (themeToggleBtn) {
    const currentTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    // HTML'deki ikonu güncelle (innerHTML yerine attribute ile)
    const themeIcon = document.getElementById('themeIcon');
    if (themeIcon) {
      themeIcon.setAttribute('data-lucide', currentTheme === 'light' ? 'sun' : 'moon');
    }

    themeToggleBtn.addEventListener('click', () => {
      let theme = document.documentElement.getAttribute('data-theme');
      const themeIcon = document.getElementById('themeIcon');
      if (theme === 'light') {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
        if (themeIcon) themeIcon.setAttribute('data-lucide', 'moon');
      } else {
        document.documentElement.setAttribute('data-theme', 'light');
        localStorage.setItem('theme', 'light');
        if (themeIcon) themeIcon.setAttribute('data-lucide', 'sun');
      }
      if (window.lucide) lucide.createIcons();
    });
  }

  const startFrontendBtn = document.getElementById('startFrontendBtn');
  if (startFrontendBtn) {
    startFrontendBtn.addEventListener('click', () => {
      // Yeni Zyricon chat arayüzünü aç
      const username = localStorage.getItem('username') || '';
      const chatUrl = username
        ? `/chat.html?username=${encodeURIComponent(username)}`
        : '/chat.html';
      window.open(chatUrl, '_blank');
    });
  }


  async function fetchProfiles() {
      const tbody = document.getElementById('profilesTableBody');
      if (!tbody) return;
      try {
          const res = await apiFetch(`${API_BASE}/admin/company/employees`);
          if (res && res.ok) {
              const data = await res.json();
              tbody.innerHTML = '';
              if (data.users && data.users.length > 0) {
                  data.users.forEach(u => {
                      tbody.innerHTML += `
                          <tr>
                              <td>${u.full_name || '-'}</td>
                              <td>${u.username}</td>
                              <td>${u.department || '-'}</td>
                              <td>${u.email || '-'}</td>
                              <td>${new Date(u.created_at).toLocaleDateString('tr-TR')}</td>
                          </tr>
                      `;
                  });
              } else {
                  tbody.innerHTML = '<tr><td colspan="5" class="text-center">Henüz çalışan bulunmuyor.</td></tr>';
              }
          }
      } catch (err) {
          console.error(err);
      }
  }

  // Profile Dropdown and Modals
  const profileDropdown = document.getElementById('profileDropdown');
  if (userProfileIcon && profileDropdown) {
      userProfileIcon.addEventListener('click', (e) => {
          e.stopPropagation();
          profileDropdown.style.display = profileDropdown.style.display === 'none' ? 'flex' : 'none';
      });
      document.addEventListener('click', () => {
          profileDropdown.style.display = 'none';
      });
  }

  const btnEditProfile = document.getElementById('btnEditProfile');
  const profileEditModal = document.getElementById('profileEditModal');
  const btnCancelProfileEdit = document.getElementById('btnCancelProfileEdit');
  const profileEditForm = document.getElementById('profileEditForm');

  if (btnEditProfile) {
      btnEditProfile.addEventListener('click', async () => {
          try {
              const res = await apiFetch(`${API_BASE}/auth/me`);
              if (res && res.ok) {
                  const data = await res.json();
                  document.getElementById('profFullName').value = data.full_name || '';
                  document.getElementById('profEmail').value = data.email || '';
                  document.getElementById('profPhone').value = data.phone || '';
                  profileEditModal.style.display = 'flex';
              }
          } catch(e) { console.error(e); }
      });
  }

  if (btnCancelProfileEdit) {
      btnCancelProfileEdit.addEventListener('click', () => {
          profileEditModal.style.display = 'none';
      });
  }

  if (profileEditForm) {
      profileEditForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const btn = profileEditForm.querySelector('button[type="submit"]');
          const originalText = btn.innerText;
          btn.innerText = 'Güncelleniyor...';
          btn.disabled = true;

          const updateData = {
              full_name: document.getElementById('profFullName').value.trim(),
              email: document.getElementById('profEmail').value.trim(),
              phone: document.getElementById('profPhone').value.trim()
          };

          try {
              const res = await apiFetch(`${API_BASE}/auth/me`, {
                  method: 'PUT',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(updateData)
              });
              if (res && res.ok) {
                  localStorage.setItem('full_name', updateData.full_name);
                  const parts = updateData.full_name.split(' ').filter(p => p.length > 0);
                  let initials = 'US';
                  if (parts.length >= 2) {
                      initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                  } else if (parts.length === 1) {
                      initials = parts[0].substring(0, 2).toUpperCase();
                  } else {
                      const uname = localStorage.getItem('username') || '';
                      if (uname) initials = uname.substring(0, 2).toUpperCase();
                  }
                  userProfileIcon.innerHTML = initials;
                  alert('Profil başarıyla güncellendi!');
                  profileEditModal.style.display = 'none';
              } else {
                  const err = await res.json();
                  alert(err.detail || 'Güncelleme hatası');
              }
          } catch(e) {
              console.error(e);
              alert('Bağlantı hatası');
          } finally {
              btn.innerText = originalText;
              btn.disabled = false;
          }
      });
  }

  const btnChangePassword = document.getElementById('btnChangePassword');
  const passwordChangeModal = document.getElementById('passwordChangeModal');
  const btnCancelPasswordChange = document.getElementById('btnCancelPasswordChange');
  const passwordChangeForm = document.getElementById('passwordChangeForm');

  if (btnChangePassword) {
      btnChangePassword.addEventListener('click', () => {
          passwordChangeForm.reset();
          passwordChangeModal.style.display = 'flex';
      });
  }

  if (btnCancelPasswordChange) {
      btnCancelPasswordChange.addEventListener('click', () => {
          passwordChangeModal.style.display = 'none';
      });
  }

  if (passwordChangeForm) {
      passwordChangeForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const pwdOld = document.getElementById('pwdOld').value;
          const pwdNew = document.getElementById('pwdNew').value;
          const pwdNewConfirm = document.getElementById('pwdNewConfirm').value;

          if (pwdNew !== pwdNewConfirm) {
              alert('Yeni şifreler eşleşmiyor!');
              return;
          }

          const btn = passwordChangeForm.querySelector('button[type="submit"]');
          const originalText = btn.innerText;
          btn.innerText = 'Değiştiriliyor...';
          btn.disabled = true;

          try {
              const res = await apiFetch(`${API_BASE}/auth/me/password`, {
                  method: 'PUT',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ old_password: pwdOld, new_password: pwdNew })
              });
              if (res && res.ok) {
                  alert('Şifre başarıyla değiştirildi!');
                  passwordChangeModal.style.display = 'none';
              } else {
                  const err = await res.json();
                  alert(err.detail || 'Şifre değiştirme hatası');
              }
          } catch(e) {
              console.error(e);
              alert('Bağlantı hatası');
          } finally {
              btn.innerText = originalText;
              btn.disabled = false;
          }
      });
  }

  await initCharts();
  refreshDashboard();

  // Sayfa tamamen yüklendikten sonra iconları oluştur
  if (window.lucide) lucide.createIcons();
});

