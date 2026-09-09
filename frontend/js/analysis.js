window.AnalysisModule = (() => {
  document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('pcap-drop-zone');
    const fileInput = document.getElementById('pcap-file-input');

    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--accent-cyan)';
        dropZone.style.background = 'rgba(0, 242, 254, 0.05)';
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-color)';
        dropZone.style.background = 'var(--bg-card)';
      }, false);
    });

    dropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) handleFile(files[0]);
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0) handleFile(fileInput.files[0]);
    });
  });

  async function handleFile(file) {
    const resultsSec = document.getElementById('pcap-results-section');
    const dropZone = document.getElementById('pcap-drop-zone');

    dropZone.innerHTML = `
      <i class="ri-loader-4-line ri-spin" style="font-size: 3.5rem; color: var(--accent-cyan); display: block; margin-bottom: 1rem;"></i>
      <h2 style="font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem;">Analyzing ${file.name}...</h2>
      <p style="color: var(--text-secondary);">Executing Scapy packet disassembly & threat detection engine...</p>
    `;

    try {
      const data = await API.uploadPCAP(file);
      
      document.getElementById('pcap-res-total').innerText = data.total_packets.toLocaleString();
      document.getElementById('pcap-res-alerts').innerText = data.alerts.length;
      document.getElementById('pcap-res-ips').innerText = Object.keys(data.top_ips || {}).length;

      const tbody = document.getElementById('pcap-alerts-table-body');
      if (data.alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="color: var(--text-muted);">No security threats identified in PCAP capture file.</td></tr>';
      } else {
        tbody.innerHTML = data.alerts.map(a => `
          <tr>
            <td><strong style="color: #fff;">${a.rule_name}</strong></td>
            <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
            <td><strong style="color: var(--accent-rose);">${a.source_ip}</strong></td>
            <td><strong style="color: var(--accent-blue);">${a.dest_ip}</strong></td>
            <td style="font-size: 0.85rem; color: var(--text-secondary);">${a.description}</td>
          </tr>
        `).join('');
      }

      resultsSec.style.display = 'block';

      // Reset Dropzone UI
      dropZone.innerHTML = `
        <i class="ri-checkbox-circle-line" style="font-size: 3.5rem; color: var(--accent-emerald); display: block; margin-bottom: 1rem;"></i>
        <h2 style="font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem;">PCAP Analysis Completed</h2>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">File <strong>${file.name}</strong> successfully processed.</p>
        <button class="btn btn-outline" onclick="document.getElementById('pcap-file-input').click()">Upload Another File</button>
      `;

    } catch (err) {
      dropZone.innerHTML = `
        <i class="ri-error-warning-line" style="font-size: 3.5rem; color: var(--accent-rose); display: block; margin-bottom: 1rem;"></i>
        <h2 style="font-size: 1.4rem; font-weight: 700; color: var(--accent-rose); margin-bottom: 0.5rem;">Analysis Failed</h2>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">${err.message}</p>
        <button class="btn btn-primary" onclick="document.getElementById('pcap-file-input').click()">Try Again</button>
      `;
    }
  }

  return {};
})();
