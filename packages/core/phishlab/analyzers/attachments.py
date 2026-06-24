from __future__ import annotations

from pathlib import Path

import yaml

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity

_RULES_DIR = Path(__file__).resolve().parents[4] / "rules"


def _load_extension_rules() -> dict[str, Severity]:
    path = _RULES_DIR / "suspicious_extensions.yml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapping: dict[str, Severity] = {}
    for _group_name, group in data.items():
        severity = Severity(group["severity"])
        for ext in group["extensions"]:
            mapping[str(ext).lower()] = severity
    return mapping


class AttachmentAnalyzer(BaseAnalyzer):
    def __init__(self) -> None:
        self._extension_severity = _load_extension_rules()

    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []

        for att in email.attachments:
            if att.has_double_extension:
                inner_exts = att.detected_extensions
                findings.append(Finding(
                    title="Double file extension detected",
                    category=Category.ATTACHMENTS,
                    severity=Severity.CRITICAL,
                    description=(
                        f"The file '{att.filename}' has multiple extensions ({', '.join(inner_exts)}). "
                        "Double extensions are a common trick to disguise executable files."
                    ),
                    evidence=f"Filename: {att.filename}, Extensions: {inner_exts}",
                    recommendation="Do not open this file. Double extensions are a strong phishing indicator.",
                    location=f"Attachment: {att.filename}",
                ))

            ext = att.extension.lower()
            if ext in self._extension_severity:
                severity = self._extension_severity[ext]
                findings.append(Finding(
                    title=f"Suspicious file type: {ext}",
                    category=Category.ATTACHMENTS,
                    severity=severity,
                    description=f"The attachment '{att.filename}' has a potentially dangerous extension ({ext}).",
                    evidence=f"Filename: {att.filename}, Extension: {ext}, MIME: {att.content_type}",
                    recommendation="Do not open this file unless you are certain of its origin and safety.",
                    location=f"Attachment: {att.filename}",
                ))

            for det_ext in att.detected_extensions:
                det_ext_lower = det_ext.lower()
                if det_ext_lower != ext and det_ext_lower in self._extension_severity:
                    severity = self._extension_severity[det_ext_lower]
                    findings.append(Finding(
                        title=f"Hidden suspicious extension: {det_ext_lower}",
                        category=Category.ATTACHMENTS,
                        severity=severity,
                        description=(
                            f"The attachment '{att.filename}' contains a hidden suspicious "
                            f"extension ({det_ext_lower}) among its multiple extensions."
                        ),
                        evidence=f"Filename: {att.filename}, Hidden extension: {det_ext_lower}",
                        recommendation="This file disguises a dangerous extension. Do not open it.",
                        location=f"Attachment: {att.filename}",
                    ))

            if att.content_type and att.extension:
                if _is_mime_mismatch(att.content_type, att.extension):
                    findings.append(Finding(
                        title="MIME type mismatch",
                        category=Category.ATTACHMENTS,
                        severity=Severity.MEDIUM,
                        description=(
                            f"The MIME type '{att.content_type}' does not match "
                            f"the file extension '{att.extension}'."
                        ),
                        evidence=f"MIME: {att.content_type}, Extension: {att.extension}",
                        recommendation="The file type may be disguised. Exercise caution.",
                        location=f"Attachment: {att.filename}",
                        confidence=0.7,
                    ))

        return findings


_MIME_EXTENSION_MAP: dict[str, set[str]] = {
    "application/pdf": {".pdf"},
    "application/msword": {".doc", ".dot"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls", ".xlt"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/vnd.ms-powerpoint": {".ppt", ".pps"},
    "application/zip": {".zip"},
    "application/x-rar-compressed": {".rar"},
    "application/gzip": {".gz", ".gzip"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/gif": {".gif"},
    "text/plain": {".txt", ".csv", ".log"},
    "text/html": {".html", ".htm"},
}


def _is_mime_mismatch(content_type: str, extension: str) -> bool:
    ct = content_type.lower().split(";")[0].strip()
    ext = extension.lower()
    if ct in ("application/octet-stream", "application/x-msdownload"):
        return False
    if ct in _MIME_EXTENSION_MAP:
        return ext not in _MIME_EXTENSION_MAP[ct]
    return False
