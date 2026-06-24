import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import RiskBadge from "../components/RiskBadge";
import { listAnalyses } from "../api/client";
import type { AnalysisSummary } from "../types";

export default function HistoryPage() {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listAnalyses().then(setAnalyses).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="page">
        <h2>Analysis History</h2>
        <div className="status-card"><div className="spinner" /> Loading...</div>
      </div>
    );
  }

  return (
    <div className="page">
      <h2>Analysis History</h2>

      {analyses.length === 0 ? (
        <p className="empty-state">
          No analyses yet. Upload an .eml file to get started.
        </p>
      ) : (
        <div className="table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>Subject</th>
                <th>From</th>
                <th>Risk</th>
                <th>Findings</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {analyses.map((a) => (
                <tr key={a.id}>
                  <td>{a.subject || "(no subject)"}</td>
                  <td className="mono">{a.from_address}</td>
                  <td>
                    <RiskBadge level={a.risk_level} score={a.risk_score} />
                  </td>
                  <td>{a.finding_count}</td>
                  <td>
                    <Link to={`/analysis/${a.id}`} className="btn btn-sm">
                      Details
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
