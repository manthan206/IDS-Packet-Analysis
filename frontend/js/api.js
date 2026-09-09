const API = {
  getToken() {
    return localStorage.getItem('ids_access_token');
  },

  setToken(token) {
    localStorage.setItem('ids_access_token', token);
  },

  clearToken() {
    localStorage.removeItem('ids_access_token');
  },

  async request(url, options = {}) {
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, { ...options, headers });
      if (response.status === 401) {
        this.clearToken();
        window.dispatchEvent(new Event('auth:unauthorized'));
        throw new Error('Unauthorized');
      }
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || 'API request failed');
      }
      return await response.json();
    } catch (err) {
      throw err;
    }
  },

  async login(username, password) {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || 'Login failed');
    }

    const data = await response.json();
    this.setToken(data.access_token);
    return data;
  },

  async getStats() {
    return this.request('/api/stats');
  },

  async getPackets(limit = 100) {
    return this.request(`/api/packets?limit=${limit}`);
  },

  async getAlerts(severity = 'ALL') {
    return this.request(`/api/alerts?severity=${severity}`);
  },

  async acknowledgeAlert(alertId) {
    return this.request(`/api/alerts/${alertId}/acknowledge`, { method: 'PUT' });
  },

  async getTopology() {
    return this.request('/api/topology');
  },

  async uploadPCAP(file) {
    const token = this.getToken();
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/api/pcap/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || 'PCAP analysis failed');
    }

    return await response.json();
  },

  async startCapture(interfaceName, bpfFilter) {
    return this.request('/api/capture/start', {
      method: 'POST',
      body: JSON.stringify({ interface: interfaceName, bpf_filter: bpfFilter, is_capturing: true })
    });
  },

  async stopCapture() {
    return this.request('/api/capture/stop', { method: 'POST' });
  },

  async downloadPDFReport() {
    const token = this.getToken();
    const response = await fetch('/api/reports/pdf', {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!response.ok) {
      throw new Error('Failed to generate PDF report');
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersentinel_security_report_${new Date().toISOString().slice(0,10)}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  }
};
