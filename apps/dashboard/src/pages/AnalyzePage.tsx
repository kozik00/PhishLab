import { useState } from "react";
import { useNavigate } from "react-router-dom";
import FileUpload from "../components/FileUpload";
import RiskBadge from "../components/RiskBadge";
import { analyzeEmail } from "../api/client";
import type { AnalysisSummary } from "../types";

export default function AnalyzePage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisSummary | null>(null);

  async function handleFile(file: File) {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyzeEmail(file);
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <h2>Analyze Email</h2>
      <p className="page-desc">
        Upload a <code>.eml</code> file to scan for phishing indicators.
      </p>

      <FileUpload onFile={handleFile} disabled={loading} />

      {loading && (
        <div className="status-card">
          <div className="spinner" />
          <span>Analyzing email...</span>
        </div>
      )}

      {error && <div className="status-card error">{error}</div>}

      {result && (
        <div className="result-card">
          <div className="result-header">
            <div>
              <h3>{result.subject || "(no subject)"}</h3>
              <span className="result-from">From: {result.from_address}</span>
            </div>
            <RiskBadge level={result.risk_level} score={result.risk_score} />
          </div>

          <div className="result-stats">
            <div className="stat">
              <span className="stat-value">{result.finding_count}</span>
              <span className="stat-label">Findings</span>
            </div>
            <div className="stat">
              <span className="stat-value">{result.risk_score}</span>
              <span className="stat-label">Risk Score</span>
            </div>
          </div>

          {result.top_contributors.length > 0 && (
            <div className="top-contributors">
              <h4>Top Contributors</h4>
              <ul>
                {result.top_contributors.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          )}

          <button
            className="btn btn-primary"
            onClick={() => navigate(`/analysis/${result.id}`)}
          >
            View Full Analysis
          </button>
        </div>
      )}
    </div>
  );
}
