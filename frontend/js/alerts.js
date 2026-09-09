window.AlertsModule = (() => {
  let alerts = [];
  let activeSeverityFilter = 'ALL';

  async function loadAlerts() {
    try {
      alerts = await API.getAlerts(activeSeverityFilter);
      renderAlerts();
    } catch (e) {}
  }

  function renderAlerts() {
    const tbody = document.getElementById('alerts-table-body');
    document.getElementById('alerts-total-count').innerText = alerts.length;

    if (alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No security alerts matching severity criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td>
          <strong style="color: #fff;">${a.rule_name}</strong>
        </td>
        <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td><strong style="color: var(--accent-rose);">${a.source_ip}</strong> ${a.source_port ? ':' + a.source_port : ''}</td>
        <td><span class="badge badge-low">${a.country || 'Unknown'}</span></td>
        <td><strong style="color: var(--accent-blue);">${a.dest_ip}</strong> ${a.dest_port ? ':' + a.dest_port : ''}</td>
        <td style="font-size: 0.85rem; color: var(--text-secondary);">${a.description}</td>
        <td>
          ${a.acknowledged 
            ? '<span style="color: var(--text-muted); font-size: 0.8rem;"><i class="ri-check-line"></i> Acked</span>' 
            : `<button class="btn btn-outline btn-ack" data-id="${a.id}" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;">Ack</button>`}
        </td>
      </tr>
    `).join('');

    // Attach event listeners to ack buttons
    document.querySelectorAll('.btn-ack').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        try {
          await API.acknowledgeAlert(id);
          loadAlerts();
        } catch (e) {}
      });
    });
  }

  function handlePacketEvent(data) {
    if (data.alerts && data.alerts.length > 0) {
      data.alerts.forEach(newAlert => {
        alerts.unshift(newAlert);
      });
      renderAlerts();
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.alert-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.alert-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeSeverityFilter = btn.getAttribute('data-sev');
        loadAlerts();
      });
    });
  });

  return {
    refresh: loadAlerts,
    handlePacketEvent
  };
})();
