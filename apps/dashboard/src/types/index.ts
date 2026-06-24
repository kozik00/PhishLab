export type RiskLevel = "low" | "medium" | "high" | "critical";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "sender_identity"
  | "authentication"
  | "links"
  | "attachments"
  | "content"
  | "brand_impersonation";

export interface Finding {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  evidence: string;
  recommendation: string;
  location: string;
  confidence: number;
  tags: string[];
}

export interface CategoryScore {
  category: Category;
  score: number;
  finding_count: number;
}

export interface AnalysisSummary {
  id: string;
  filename: string;
  subject: string;
  from_address: string;
  risk_score: number;
  risk_level: RiskLevel;
  finding_count: number;
  top_contributors: string[];
}

export interface AnalysisDetail {
  id: string;
  filename: string;
  subject: string;
  from_address: string;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
  findings: Finding[];
  result: {
    risk_score: number;
    risk_level: RiskLevel;
    category_scores: CategoryScore[];
    top_contributors: string[];
  };
  email: EmailSummary;
}

export interface EmailSummary {
  subject: string;
  from_address: string;
  from_display_name: string;
  reply_to: string;
  return_path: string;
  to: string[];
  date_raw: string | null;
  text_body: string | null;
  authentication_results: string;
  links: EmailLink[];
  attachments: EmailAttachment[];
}

export interface EmailLink {
  visible_text: string;
  href: string;
  domain: string;
  is_ip_based: boolean;
  is_shortened: boolean;
  uses_https: boolean;
}

export interface EmailAttachment {
  filename: string;
  extension: string;
  size_bytes: number;
  has_double_extension: boolean;
  is_suspicious_type: boolean;
}

export interface TrainingSample {
  id: string;
  title: string;
  description: string;
  difficulty: string;
  tags: string[];
}

export interface TrainingSampleDetail extends TrainingSample {
  email: EmailSummary & {
    link_count: number;
    attachment_count: number;
  };
}

export interface SampleAnalysis {
  id: string;
  risk_score: number;
  risk_level: RiskLevel;
  finding_count: number;
  findings: Finding[];
  category_scores: CategoryScore[];
  top_contributors: string[];
}

export interface QuizAnswer {
  sample_id: string;
  user_answer: boolean;
  correct: boolean;
  explanation: string;
  indicators?: string[];
}

export interface QuizScore {
  total: number;
  correct: number;
  incorrect: number;
  score_percent: number;
}

export interface QuizResult {
  score: QuizScore;
  results: QuizAnswer[];
}
