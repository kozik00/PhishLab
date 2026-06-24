import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listTrainingSamples, getTrainingSample, submitQuiz } from "../api/client";
import type { TrainingSample, TrainingSampleDetail, QuizResult } from "../types";

export default function QuizPage() {
  const navigate = useNavigate();
  const [samples, setSamples] = useState<TrainingSample[]>([]);
  const [current, setCurrent] = useState(0);
  const [sampleDetail, setSampleDetail] = useState<TrainingSampleDetail | null>(null);
  const [answers, setAnswers] = useState<Record<string, boolean>>({});
  const [result, setResult] = useState<QuizResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    listTrainingSamples().then((s) => {
      setSamples(s);
      setLoading(false);
    });
  }, []);

  useEffect(() => {
    if (samples.length === 0 || result) return;
    setSampleDetail(null);
    getTrainingSample(samples[current].id).then(setSampleDetail);
  }, [current, samples, result]);

  function handleAnswer(isPhishing: boolean) {
    const id = samples[current].id;
    setAnswers((prev) => ({ ...prev, [id]: isPhishing }));
    if (current < samples.length - 1) {
      setCurrent((c) => c + 1);
    }
  }

  async function handleSubmit() {
    setSubmitting(true);
    const res = await submitQuiz(answers);
    setResult(res);
    setSubmitting(false);
  }

  const allAnswered = Object.keys(answers).length === samples.length;
  const currentAnswered = samples[current] && samples[current].id in answers;

  if (loading) {
    return (
      <div className="page">
        <h2>Phishing Quiz</h2>
        <div className="status-card"><div className="spinner" /> Loading...</div>
      </div>
    );
  }

  if (result) {
    return (
      <div className="page">
        <h2>Quiz Results</h2>
        <div className="quiz-score-card">
          <div className="quiz-score-main">
            <span className="quiz-score-number">{result.score.score_percent.toFixed(0)}%</span>
            <span className="quiz-score-detail">
              {result.score.correct} / {result.score.total} correct
            </span>
          </div>
        </div>
        <div className="quiz-results-list">
          {result.results.map((r) => (
            <div
              key={r.sample_id}
              className={`quiz-result-item ${r.correct ? "correct" : "incorrect"}`}
            >
              <span className="quiz-result-id">{r.sample_id}</span>
              <span className={`quiz-result-badge ${r.correct ? "correct" : "incorrect"}`}>
                {r.correct ? "Correct" : "Wrong"}
              </span>
              <p className="quiz-result-explanation">{r.explanation}</p>
            </div>
          ))}
        </div>
        <button className="btn btn-primary" onClick={() => navigate("/training")}>
          Back to Training
        </button>
      </div>
    );
  }

  return (
    <div className="page">
      <h2>Phishing Quiz</h2>
      <div className="quiz-progress">
        Question {current + 1} of {samples.length}
        <div className="quiz-progress-bar">
          <div
            className="quiz-progress-fill"
            style={{ width: `${(Object.keys(answers).length / samples.length) * 100}%` }}
          />
        </div>
      </div>

      {sampleDetail ? (
        <div className="quiz-question">
          <h3>{sampleDetail.title}</h3>
          <div className="sample-email-preview">
            <dl className="detail-grid">
              <dt>Subject</dt>
              <dd>{sampleDetail.email.subject}</dd>
              <dt>From</dt>
              <dd>
                {sampleDetail.email.from_display_name} &lt;{sampleDetail.email.from_address}&gt;
              </dd>
              <dt>Reply-To</dt>
              <dd>{sampleDetail.email.reply_to || "—"}</dd>
              <dt>Auth</dt>
              <dd><code>{sampleDetail.email.authentication_results || "—"}</code></dd>
            </dl>
            {sampleDetail.email.text_body && (
              <pre className="email-body">{sampleDetail.email.text_body}</pre>
            )}
          </div>

          {!currentAnswered ? (
            <div className="answer-buttons">
              <button className="btn btn-danger" onClick={() => handleAnswer(true)}>
                Phishing
              </button>
              <button className="btn btn-success" onClick={() => handleAnswer(false)}>
                Legitimate
              </button>
            </div>
          ) : (
            <div className="answered-badge">Answered</div>
          )}
        </div>
      ) : (
        <div className="status-card"><div className="spinner" /> Loading question...</div>
      )}

      <div className="quiz-nav">
        <button
          className="btn btn-sm"
          disabled={current === 0}
          onClick={() => setCurrent((c) => c - 1)}
        >
          Previous
        </button>
        <div className="quiz-dots">
          {samples.map((s, i) => (
            <button
              key={s.id}
              className={`quiz-dot ${i === current ? "current" : ""} ${s.id in answers ? "answered" : ""}`}
              onClick={() => setCurrent(i)}
            />
          ))}
        </div>
        {current < samples.length - 1 ? (
          <button className="btn btn-sm" onClick={() => setCurrent((c) => c + 1)}>
            Next
          </button>
        ) : (
          <button
            className="btn btn-primary"
            disabled={!allAnswered || submitting}
            onClick={handleSubmit}
          >
            {submitting ? "Submitting..." : "Submit Quiz"}
          </button>
        )}
      </div>
    </div>
  );
}
