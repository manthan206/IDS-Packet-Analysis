window.DashboardModule = (() => {
  let rateChart = null;
  let protoChart = null;
  let rateData = Array(20).fill(0);
  let rateLabels = Array(20).fill('');

  function initCharts() {
    // 1. Packet Rate Line Chart
    const rateOptions = {
      series: [{ name: 'Packets / Sec', data: rateData }],
      chart: { type: 'area', height: 280, toolbar: { show: false }, animations: { enabled: true, dynamicAnimation: { speed: 300 } }, background: 'transparent' },
      colors: ['#00f2fe'],
      stroke: { curve: 'smooth', width: 3 },
      fill: { type: 'gradient', gradient: { opacityFrom: 0.5, opacityTo: 0.05 } },
      dataLabels: { enabled: false },
      theme: { mode: 'dark' },
      xaxis: { categories: rateLabels, labels: { show: false } },
      yaxis: { min: 0, labels: { style: { colors: '#94a3b8' } } },
      grid: { borderColor: 'rgba(255, 255, 255, 0.05)' }
    };
    rateChart = new ApexCharts(document.getElementById('chart-packet-rate'), rateOptions);
    rateChart.render();

    // 2. Protocol Distribution Donut Chart
    const protoOptions = {
      series: [40, 25, 15, 10, 10],
      labels: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'],
      chart: { type: 'donut', height: 280, background: 'transparent' },
      colors: ['#00f2fe', '#4facfe', '#10b981', '#f59e0b', '#a855f7'],
      theme: { mode: 'dark' },
      legend: { position: 'bottom', labels: { colors: '#94a3b8' } },
      dataLabels: { enabled: false },
      stroke: { show: false }
    };
    protoChart = new ApexCharts(document.getElementById('chart-protocol-dist'), protoOptions);
    protoChart.render();
  }

  function updateStats(stats) {
    document.getElementById('kpi-total-packets').innerText = stats.total_packets.toLocaleString();
    document.getElementById('kpi-critical-alerts').innerText = stats.critical_alerts;
    document.getElementById('kpi-high-alerts').innerText = stats.high_alerts;
    document.getElementById('kpi-bandwidth').innerText = stats.bandwidth_kbps;

    // Update line chart
    rateData.push(stats.packets_per_second);
    rateData.shift();
    if (rateChart) {
      rateChart.updateSeries([{ data: rateData }]);
    }

    // Update Donut Chart
    if (stats.protocol_distribution && protoChart) {
      const labels = Object.keys(stats.protocol_distribution);
      const values = Object.values(stats.protocol_distribution);
      if (labels.length > 0) {
        protoChart.updateOptions({ labels, series: values });
      }
    }

    // Update Top Talkers Table
    if (stats.top_sources) {
      const tbody = document.getElementById('table-top-talkers');
      if (stats.top_sources.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="color: var(--text-muted);">No active traffic recorded.</td></tr>';
      } else {
        tbody.innerHTML = stats.top_sources.map(s => `
          <tr>
            <td><strong style="color: var(--accent-cyan);">${s.ip}</strong></td>
            <td><span class="badge badge-low">${s.country}</span></td>
            <td>${s.count} pkts</td>
          </tr>
        `).join('');
      }
    }
  }

  function handlePacketEvent(event) {
    if (event.alerts && event.alerts.length > 0) {
      const feed = document.getElementById('live-alert-feed');
      event.alerts.forEach(alert => {
        const item = document.createElement('div');
        item.className = 'glass-panel';
        item.style.padding = '0.75rem 1rem';
        item.style.borderLeft = `4px solid ${alert.severity === 'CRITICAL' ? 'var(--accent-rose)' : 'var(--accent-amber)'}`;
        item.style.display = 'flex';
        item.style.justifyContent = 'space-between';
        item.style.alignItems = 'center';
        
        item.innerHTML = `
          <div>
            <div style="font-weight: 700; font-size: 0.9rem; color: #fff;">${alert.rule_name}</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary);">${alert.description}</div>
          </div>
          <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
        `;

        if (feed.children[0] && feed.children[0].innerText.includes('Listening for real-time')) {
          feed.innerHTML = '';
        }
        feed.prepend(item);
        if (feed.children.length > 10) feed.removeChild(feed.lastChild);
      });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    initCharts();
  });

  return {
    refresh: async () => {
      try {
        const stats = await API.getStats();
        updateStats(stats);

        const recentAlerts = await API.getAlerts('ALL');
        if (recentAlerts && recentAlerts.length > 0) {
          const feed = document.getElementById('live-alert-feed');
          if (feed) {
            feed.innerHTML = recentAlerts.slice(0, 5).map(alert => `
              <div class="glass-panel" style="padding: 0.75rem 1rem; border-left: 4px solid ${alert.severity === 'CRITICAL' ? 'var(--accent-rose)' : 'var(--accent-amber)'}; display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: 700; font-size: 0.9rem; color: #fff;">${alert.rule_name}</div>
                  <div style="font-size: 0.8rem; color: var(--text-secondary);">${alert.description}</div>
                </div>
                <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
              </div>
            `).join('');
          }
        }
      } catch (e) {}
    },
    updateStats,
    handlePacketEvent
  };
})();
