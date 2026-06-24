import type {
  AnalysisDetail,
  AnalysisSummary,
  QuizAnswer,
  QuizResult,
  SampleAnalysis,
  TrainingSample,
  TrainingSampleDetail,
} from "../types";

const BASE = "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status}: ${body}`);
  }
  return res.json();
}

export async function analyzeEmail(file: File): Promise<AnalysisSummary> {
  const form = new FormData();
  form.append("file", file);
  return request("/analyze", { method: "POST", body: form });
}

export async function listAnalyses(
  limit = 50,
  offset = 0
): Promise<AnalysisSummary[]> {
  return request(`/analyses?limit=${limit}&offset=${offset}`);
}

export async function getAnalysis(id: string): Promise<AnalysisDetail> {
  return request(`/analyses/${id}`);
}

export async function getReport(
  id: string,
  format: "json" | "markdown" | "html" | "user"
): Promise<string> {
  const res = await fetch(`${BASE}/analyses/${id}/report?format=${format}`);
  if (!res.ok) throw new Error(`${res.status}`);
  return res.text();
}

export async function listTrainingSamples(): Promise<TrainingSample[]> {
  return request("/training/samples");
}

export async function getTrainingSample(
  id: string
): Promise<TrainingSampleDetail> {
  return request(`/training/samples/${id}`);
}

export async function getSampleAnalysis(id: string): Promise<SampleAnalysis> {
  return request(`/training/samples/${id}/analysis`);
}

export async function submitAnswer(
  sampleId: string,
  userAnswer: boolean
): Promise<QuizAnswer> {
  return request("/training/answer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sample_id: sampleId, user_answer: userAnswer }),
  });
}

export async function submitQuiz(
  answers: Record<string, boolean>
): Promise<QuizResult> {
  return request("/training/quiz", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ answers }),
  });
}
