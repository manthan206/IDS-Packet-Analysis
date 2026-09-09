window.SettingsModule = (() => {
  document.addEventListener('DOMContentLoaded', () => {
    const btnStart = document.getElementById('btn-start-engine');
    const btnStop = document.getElementById('btn-stop-engine');

    if (btnStart) {
      btnStart.addEventListener('click', async () => {
        const iface = document.getElementById('setting-interface').value;
        const bpf = document.getElementById('setting-bpf').value;
        try {
          const res = await API.startCapture(iface, bpf);
          alert(res.message || 'Capture started successfully');
          document.getElementById('engine-status-dot').style.background = 'var(--accent-emerald)';
          document.getElementById('engine-status-text').innerText = 'Engine: Active (24/7)';
        } catch (e) {
          alert('Failed to start capture engine: ' + e.message);
        }
      });
    }

    if (btnStop) {
      btnStop.addEventListener('click', async () => {
        try {
          const res = await API.stopCapture();
          alert(res.message || 'Capture stopped');
          document.getElementById('engine-status-dot').style.background = 'var(--accent-rose)';
          document.getElementById('engine-status-text').innerText = 'Engine: Stopped';
        } catch (e) {
          alert('Failed to stop capture engine: ' + e.message);
        }
      });
    }
  });

  return {};
})();
