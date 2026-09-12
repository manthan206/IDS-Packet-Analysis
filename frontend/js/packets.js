window.PacketsModule = (() => {
  let isPaused = false;
  let packets = [];
  const maxPackets = 150;

  function renderTable() {
    const tbody = document.getElementById('packets-table-body');
    const searchVal = document.getElementById('packet-search-input').value.toLowerCase();
    const protoVal = document.getElementById('packet-proto-filter').value;

    const filtered = packets.filter(p => {
      const matchesSearch = !searchVal || 
        p.source_ip.toLowerCase().includes(searchVal) ||
        p.dest_ip.toLowerCase().includes(searchVal) ||
        (p.info && p.info.toLowerCase().includes(searchVal));

      const matchesProto = protoVal === 'ALL' || p.protocol === protoVal;

      return matchesSearch && matchesProto;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No packets match current filter.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(p => `
      <tr>
        <td class="mono" style="font-size: 0.8rem; color: var(--text-muted);">${p.timestamp ? (p.timestamp.includes('T') ? p.timestamp.split('T')[1].slice(0, 8) : p.timestamp) : new Date().toLocaleTimeString()}</td>
        <td><strong style="color: var(--accent-cyan);">${p.source_ip}</strong></td>
        <td class="mono">${p.source_port || '-'}</td>
        <td><strong style="color: var(--accent-blue);">${p.dest_ip}</strong></td>
        <td class="mono">${p.dest_port || '-'}</td>
        <td><span class="badge badge-low">${p.protocol}</span></td>
        <td class="mono">${p.length} B</td>
        <td style="font-size: 0.85rem; color: var(--text-secondary); max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${p.info || p.flags || '-'}</td>
      </tr>
    `).join('');
  }

  function handlePacketEvent(data) {
    if (isPaused || !data.packet) return;
    packets.unshift(data.packet);
    if (packets.length > maxPackets) packets.pop();
    renderTable();
  }

  document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('packet-search-input');
    const protoFilter = document.getElementById('packet-proto-filter');
    const btnPause = document.getElementById('btn-pause-packets');
    const btnClear = document.getElementById('btn-clear-packets');

    if (searchInput) searchInput.addEventListener('input', renderTable);
    if (protoFilter) protoFilter.addEventListener('change', renderTable);
    
    if (btnPause) {
      btnPause.addEventListener('click', () => {
        isPaused = !isPaused;
        btnPause.innerHTML = isPaused ? '<i class="ri-play-circle-line"></i> Resume Stream' : '<i class="ri-pause-circle-line"></i> Pause Stream';
        btnPause.classList.toggle('btn-primary', isPaused);
      });
    }

    if (btnClear) {
      btnClear.addEventListener('click', () => {
        packets = [];
        renderTable();
      });
    }
  });

  return {
    refresh: async () => {
      try {
        const initial = await API.getPackets(50);
        packets = initial;
        renderTable();
      } catch (e) {}
    },
    handlePacketEvent
  };
})();
