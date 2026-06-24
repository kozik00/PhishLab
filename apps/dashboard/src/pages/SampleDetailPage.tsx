import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import RiskGauge from "../components/RiskGauge";
import FindingsTable from "../components/FindingsTable";
import {
  getTrainingSample,
  getSampleAnalysis,
  submitAnswer,
} from "../api/client";
import type {
  TrainingSampleDetail,
  SampleAnalysis,
  QuizAnswer,
} from "../types";

export default function SampleDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [sample, setSample] = useState<TrainingSampleDetail | null>(null);
  const [analysis, setAnalysis] = useState<SampleAnalysis | null>(null);
  const [answer, setAnswer] = useState<QuizAnswer | null>(null);
  const [loading, setLoading] = useState(true);
  const [showAnalysis, setShowAnalysis] = useState(false);

  useEffect(() => {
    if (!id) return;
    getTrainingSample(id)
      .then(setSample)
      .finally(() => setLoading(false));
  }, [id]);

  async function handleAnswer(isPhishing: boolean) {
    if (!id) return;
    const result = await submitAnswer(id, isPhishing);
    setAnswer(result);
  }

  async function handleShowAnalysis() {
    if (!id) return;
    const result = await getSampleAnalysis(id);
    setAnalysis(result);
    setShowAnalysis(true);
  }

  if (loading || !sample) {
    return (
      <div className="page">
        <div className="status-card"><div className="spinner" /> Loading sample...</div>
      </div>
    );
  }

  return (
    <div className="page">
      <h2>{sample.title}</h2>
      <p className="page-desc">{sample.description}</p>
      <span className={`difficulty difficulty-${sample.difficulty}`}>
        {sample.difficulty}
      </span>

      <div className="sample-email-preview">
        <h3>Email Preview</h3>
        <dl className="detail-grid">
          <dt>Subject</dt>
          <dd>{sample.email.subject}</dd>
          <dt>From</dt>
          <dd>
            {sample.email.from_display_name} &lt;{sample.email.from_address}&gt;
          </dd>
          <dt>Reply-To</dt>
          <dd>{sample.email.reply_to || "—"}</dd>
          <dt>To</dt>
          <dd>{sample.email.to?.join(", ") || "—"}</dd>
          <dt>Date</dt>
          <dd>{sample.email.date_raw || "—"}</dd>
          <dt>Auth</dt>
          <dd><code>{sample.email.authentication_results || "—"}</code></dd>
          <dt>Links</dt>
          <dd>{sample.email.link_count}</dd>
          <dt>Attachments</dt>
          <dd>{sample.email.attachment_count}</dd>
        </dl>

        {sample.email.text_body && (
          <details className="email-body-section">
            <summary>Email Body</summary>
            <pre className="email-body">{sample.email.text_body}</pre>
          </details>
        )}

        {sample.email.links.length > 0 && (
          <details className="email-body-section">
            <summary>Links ({sample.email.links.length})</summary>
            <ul className="link-list">
              {sample.email.links.map((l, i) => (
                <li key={i}>
                  <span className="mono">{l.domain}</span>
                  {l.is_ip_based && <span className="flag">IP</span>}
                  {l.is_shortened && <span className="flag">Shortened</span>}
                  {!l.uses_https && <span className="flag">HTTP</span>}
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>

      {!answer ? (
        <div className="answer-section">
          <h3>Is this email a phishing attempt?</h3>
          <div className="answer-buttons">
            <button
              className="btn btn-danger"
              onClick={() => handleAnswer(true)}
            >
              Yes, it's phishing
            </button>
            <button
              className="btn btn-success"
              onClick={() => handleAnswer(false)}
            >
              No, it's legitimate
            </button>
          </div>
        </div>
      ) : (
        <div className={`answer-result ${answer.correct ? "correct" : "incorrect"}`}>
          <h3>{answer.correct ? "Correct!" : "Incorrect"}</h3>
          <p>{answer.explanation}</p>
          {answer.indicators && answer.indicators.length > 0 && (
            <div className="indicators">
              <h4>Key Indicators</h4>
              <ul>
                {answer.indicators.map((ind, i) => (
                  <li key={i}>{ind}</li>
                ))}
              </ul>
            </div>
          )}
          {!showAnalysis && (
            <button className="btn btn-primary" onClick={handleShowAnalysis}>
              Show Full Analysis
            </button>
          )}
        </div>
      )}

      {showAnalysis && analysis && (
        <div className="analysis-reveal">
          <h3>Automated Analysis</h3>
          <RiskGauge score={analysis.risk_score} level={analysis.risk_level} />
          <FindingsTable findings={analysis.findings} />
        </div>
      )}
    </div>
  );
}
