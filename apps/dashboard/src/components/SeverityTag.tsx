import type { Severity } from "../types";

export default function SeverityTag({ severity }: { severity: Severity }) {
  return <span className={`severity-tag severity-${severity}`}>{severity}</span>;
}
