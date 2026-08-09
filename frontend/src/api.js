const BASE = import.meta.env.VITE_API_BASE || "";

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, options);
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (body.detail) detail = body.detail;
    } catch {
      /* non-JSON error body - keep the status-based message */
    }
    throw new Error(detail);
  }
  return response.json();
}

export const api = {
  health: () => request("/api/health"),
  ontology: () => request("/api/ontology"),
  listDatasets: () => request("/api/datasets"),
  getDataset: (id) => request(`/api/datasets/${id}`),
  getSchema: (id) => request(`/api/datasets/${id}/schema`),
  /* Corrects the inferred mapping and re-runs the whole analysis. */
  overrideSchema: (id, overrides) =>
    request(`/api/datasets/${id}/schema`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ overrides }),
    }),
  getOverview: (id) => request(`/api/datasets/${id}/overview`),
  getTimeline: (id, bucketMinutes = 30) =>
    request(`/api/datasets/${id}/timeline?bucket_minutes=${bucketMinutes}`),
  getAlerts: (id, classification) =>
    request(
      `/api/datasets/${id}/alerts${classification ? `?classification=${classification}` : ""}`
    ),
  getAnalytics: (id) => request(`/api/datasets/${id}/analytics`),
  investigateIp: (id, ip) => request(`/api/datasets/${id}/ips/${encodeURIComponent(ip)}`),
  upload: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/api/datasets", { method: "POST", body: form });
  },
};
