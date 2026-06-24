import type { Finding } from "../types";
import SeverityTag from "./SeverityTag";

interface Props {
  findings: Finding[];
}

export default function FindingsTable({ findings }: Props) {
  if (findings.length === 0) {
    return <p className="empty-state">No findings detected.</p>;
  }

  return (
    <div className="table-wrapper">
      <table className="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Category</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={f.id || i}>
              <td>
                <SeverityTag severity={f.severity} />
              </td>
              <td className="finding-title">{f.title}</td>
              <td>{f.category.replace("_", " ")}</td>
              <td>
                <div className="finding-desc">{f.description}</div>
                {f.evidence && (
                  <code className="finding-evidence">{f.evidence}</code>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
