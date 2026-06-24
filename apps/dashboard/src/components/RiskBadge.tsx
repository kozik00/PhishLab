import type { RiskLevel } from "../types";

interface Props {
  level: RiskLevel;
  score: number;
}

export default function RiskBadge({ level, score }: Props) {
  return (
    <span className={`risk-badge risk-${level}`}>
      {score} — {level.toUpperCase()}
    </span>
  );
}
