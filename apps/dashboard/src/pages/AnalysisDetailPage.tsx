import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import RiskGauge from "../components/RiskGauge";
import FindingsTable from "../components/FindingsTable";
import { getAnalysis, getReport } from "../api/client";
import type { AnalysisDetail } from "../types";

export default function AnalysisDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<AnalysisDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"findings" | "email" | "links">("findings");

  useEffect(() => {
    if (!id) return;
    getAnalysis(id)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  async function downloadReport(format: "html" | "markdown" | "json" | "user") {
    if (!id) return;
    const content = await getReport(id, format);
    const ext = format === "html" ? "html" : format === "json" ? "json" : "md";
    const blob = new Blob([content], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishlab-report-${id}.${ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  if (loading) {
    return (
      <div className="page">
        <div className="status-card"><div className="spinner" /> Loading analysis...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="page">
        <div className="status-card error">{error || "Analysis not found"}</div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="detail-header">
        <div>
          <h2>{data.subject || "(no subject)"}</h2>
          <span className="result-from">From: {data.from_address}</span>
          {data.created_at && (
            <span className="result-date">
              {new Date(data.created_at).toLocaleString()}
            </span>
          )}
        </div>
      </div>

      <RiskGauge score={data.risk_score} level={data.risk_level} />

      <div className="report-actions">
        <span>Download Report:</span>
        <button className="btn btn-sm" onClick={() => downloadReport("html")}>HTML</button>
        <button className="btn btn-sm" onClick={() => downloadReport("markdown")}>Markdown</button>
        <button className="btn btn-sm" onClick={() => downloadReport("json")}>JSON</button>
        <button className="btn btn-sm" onClick={() => downloadReport("user")}>User-Friendly</button>
      </div>

      <div className="tabs">
        <button
          className={`tab ${tab === "findings" ? "active" : ""}`}
          onClick={() => setTab("findings")}
        >
          Findings ({data.findings.length})
        </button>
        <button
          className={`tab ${tab === "email" ? "active" : ""}`}
          onClick={() => setTab("email")}
        >
          Email Details
        </button>
        <button
          className={`tab ${tab === "links" ? "active" : ""}`}
          onClick={() => setTab("links")}
        >
          Links & Attachments
        </button>
      </div>

      {tab === "findings" && <FindingsTable findings={data.findings} />}

      {tab === "email" && (
        <div className="email-detail">
          <dl className="detail-grid">
            <dt>Subject</dt>
            <dd>{data.email.subject}</dd>
            <dt>From</dt>
            <dd>
              {data.email.from_display_name} &lt;{data.email.from_address}&gt;
            </dd>
            <dt>Reply-To</dt>
            <dd>{data.email.reply_to || "—"}</dd>
            <dt>Return-Path</dt>
            <dd>{data.email.return_path || "—"}</dd>
            <dt>To</dt>
            <dd>{data.email.to?.join(", ") || "—"}</dd>
            <dt>Date</dt>
            <dd>{data.email.date_raw || "—"}</dd>
            <dt>Auth Results</dt>
            <dd><code>{data.email.authentication_results || "—"}</code></dd>
          </dl>
          {data.email.text_body && (
            <details className="email-body-section">
              <summary>Email Body (text)</summary>
              <pre className="email-body">{data.email.text_body}</pre>
            </details>
          )}
        </div>
      )}

      {tab === "links" && (
        <div className="links-attachments">
          <h3>Links ({data.email.links?.length || 0})</h3>
          {data.email.links?.length ? (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Display Text</th>
                    <th>Domain</th>
                    <th>Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {data.email.links.map((l, i) => (
                    <tr key={i}>
                      <td>{l.visible_text || "—"}</td>
                      <td className="mono">{l.domain}</td>
                      <td>
                        {l.is_ip_based && <span className="flag">IP</span>}
                        {l.is_shortened && <span className="flag">Shortened</span>}
                        {!l.uses_https && <span className="flag">HTTP</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty-state">No links found.</p>
          )}

          <h3>Attachments ({data.email.attachments?.length || 0})</h3>
          {data.email.attachments?.length ? (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Filename</th>
                    <th>Extension</th>
                    <th>Size</th>
                    <th>Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {data.email.attachments.map((a, i) => (
                    <tr key={i}>
                      <td>{a.filename}</td>
                      <td className="mono">{a.extension}</td>
                      <td>{(a.size_bytes / 1024).toFixed(1)} KB</td>
                      <td>
                        {a.has_double_extension && (
                          <span className="flag danger">Double Ext</span>
                        )}
                        {a.is_suspicious_type && (
                          <span className="flag danger">Suspicious</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="empty-state">No attachments found.</p>
          )}
        </div>
      )}
    </div>
  );
}
