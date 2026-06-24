import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listTrainingSamples } from "../api/client";
import type { TrainingSample } from "../types";

export default function TrainingPage() {
  const navigate = useNavigate();
  const [samples, setSamples] = useState<TrainingSample[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listTrainingSamples().then(setSamples).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="page">
        <h2>Phishing Awareness Training</h2>
        <div className="status-card"><div className="spinner" /> Loading...</div>
      </div>
    );
  }

  return (
    <div className="page">
      <h2>Phishing Awareness Training</h2>
      <p className="page-desc">
        Practice identifying phishing emails. Examine each sample and decide
        whether it's a phishing attempt or a legitimate email.
      </p>

      <div className="training-actions">
        <button
          className="btn btn-primary"
          onClick={() => navigate("/training/quiz")}
        >
          Take the Quiz ({samples.length} questions)
        </button>
      </div>

      <div className="sample-grid">
        {samples.map((s) => (
          <div
            key={s.id}
            className="sample-card"
            onClick={() => navigate(`/training/${s.id}`)}
          >
            <div className="sample-card-header">
              <h3>{s.title}</h3>
              <span className={`difficulty difficulty-${s.difficulty}`}>
                {s.difficulty}
              </span>
            </div>
            <p>{s.description}</p>
            <div className="sample-tags">
              {s.tags.map((t) => (
                <span key={t} className="tag">{t}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
