import type { RiskLevel } from "../types";

interface Props {
  score: number;
  level: RiskLevel;
}

export default function RiskGauge({ score, level }: Props) {
  return (
    <div className="risk-gauge">
      <div className="risk-gauge-bar">
        <div
          className={`risk-gauge-fill risk-${level}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <div className="risk-gauge-labels">
        <span>0</span>
        <span className={`risk-gauge-score risk-${level}`}>
          {score} — {level.toUpperCase()}
        </span>
        <span>100</span>
      </div>
    </div>
  );
}
