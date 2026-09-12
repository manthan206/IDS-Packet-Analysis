let socket = null;
let currentView = 'dashboard-view';

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  setupPDFButtons();
  initAuth();
});

function initNavigation() {
  const sidebar = document.querySelector('.sidebar');
  const btnToggle = document.getElementById('btn-sidebar-toggle');

  if (btnToggle && sidebar) {
    btnToggle.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
    });
  }

  const navItems = document.querySelectorAll('.nav-item, .nav-item-link');
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetView = item.getAttribute('data-target');
      if (!targetView) return;
      
      if (sidebar) sidebar.classList.remove('mobile-open');
      switchView(targetView);
    });
  });
}

function switchView(viewId) {
  const mainContent = document.querySelector('.main-content');
  if (mainContent) mainContent.scrollTop = 0;
  window.scrollTo(0, 0);

  document.querySelectorAll('.view-container').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

  const activeView = document.getElementById(viewId);
  if (activeView) activeView.classList.add('active');

  const activeNav = document.querySelector(`.nav-item[data-target="${viewId}"]`);
  if (activeNav) activeNav.classList.add('active');

  currentView = viewId;

  // Update Header Title
  const titles = {
    'dashboard-view': 'Network Security Dashboard',
    'packets-view': 'Live Packet Inspection Stream',
    'alerts-view': 'Intrusion Detection Threat Center',
    'analysis-view': 'PCAP File Offline Deep Inspection',
    'topology-view': 'Network Communication Topology',
    'reports-view': 'Executive Threat Analysis & Security Reports',
    'settings-view': 'System Capture & Security Engine Settings'
  };
  document.getElementById('page-title').innerText = titles[viewId] || 'Dashboard';

  // Trigger View Specific Refresh
  if (viewId === 'dashboard-view' && window.DashboardModule) window.DashboardModule.refresh();
  if (viewId === 'packets-view' && window.PacketsModule) window.PacketsModule.refresh();
  if (viewId === 'alerts-view' && window.AlertsModule) window.AlertsModule.refresh();
  if (viewId === 'topology-view' && window.TopologyModule) window.TopologyModule.refresh();
}

function setupPDFButtons() {
  const btnHeader = document.getElementById('btn-header-pdf');
  const btnMain = document.getElementById('btn-main-pdf-download');

  const downloadHandler = async () => {
    try {
      if (btnHeader) btnHeader.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> Generating...';
      if (btnMain) btnMain.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> Generating PDF...';
      
      await API.downloadPDFReport();
    } catch (err) {
      alert('Failed to generate PDF report: ' + err.message);
    } finally {
      if (btnHeader) btnHeader.innerHTML = '<i class="ri-file-pdf-fill"></i> Export PDF';
      if (btnMain) btnMain.innerHTML = '<i class="ri-file-pdf-fill" style="font-size: 1.25rem;"></i> Download PDF Security Report';
    }
  };

  if (btnHeader) btnHeader.addEventListener('click', downloadHandler);
  if (btnMain) btnMain.addEventListener('click', downloadHandler);
}

function initAuth() {
  const loginModal = document.getElementById('login-modal');
  const btnLogout = document.getElementById('btn-logout');

  if (loginModal) {
    loginModal.classList.remove('active');
    loginModal.style.display = 'none';
  }

  if (btnLogout) {
    btnLogout.style.display = 'none';
  }

  // Auto-start real-time dashboard & stats engine directly without login screen
  initWebSocket();
  startStatsPolling();
}

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    console.log('WebSocket Connected to CyberSentinel IDS Stream');
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'PACKET_EVENT') {
        if (window.DashboardModule) window.DashboardModule.handlePacketEvent(data);
        if (window.PacketsModule) window.PacketsModule.handlePacketEvent(data);
        if (window.AlertsModule) window.AlertsModule.handlePacketEvent(data);
      }
    } catch (e) {
      console.error('Error parsing WS message', e);
    }
  };

  socket.onclose = () => {
    console.log('WebSocket Connection Closed. Retrying in 3s...');
    setTimeout(initWebSocket, 3000);
  };
}

function startStatsPolling() {
  setInterval(async () => {
    try {
      const stats = await API.getStats();
      document.getElementById('header-pps').innerText = stats.packets_per_second;
      document.getElementById('header-threats').innerText = stats.critical_alerts + stats.high_alerts;
      if (window.DashboardModule) window.DashboardModule.updateStats(stats);
    } catch (e) {}
  }, 3000);
}
