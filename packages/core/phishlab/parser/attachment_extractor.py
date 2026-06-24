from __future__ import annotations

import hashlib
import os
from email.message import Message

from phishlab.models.email import EmailAttachment

_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    ".jar", ".hta", ".cpl", ".inf", ".reg",
    ".iso", ".img", ".vhd",
}


def extract_attachments(msg: Message) -> list[EmailAttachment]:
    attachments: list[EmailAttachment] = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in content_disposition and "inline" not in content_disposition:
            continue

        filename = part.get_filename() or ""
        if not filename:
            continue

        payload = part.get_payload(decode=True) or b""
        content_type = part.get_content_type() or ""
        size_bytes = len(payload)
        sha256 = hashlib.sha256(payload).hexdigest()

        extension = ""
        detected_extensions: list[str] = []
        parts = filename.rsplit(".", maxsplit=1)
        if len(parts) > 1:
            extension = f".{parts[1].lower()}"

        all_dots = filename.split(".")
        if len(all_dots) > 2:
            detected_extensions = [f".{ext.lower()}" for ext in all_dots[1:]]

        has_double_extension = len(detected_extensions) > 1
        is_suspicious = extension.lower() in _SUSPICIOUS_EXTENSIONS or any(
            ext.lower() in _SUSPICIOUS_EXTENSIONS for ext in detected_extensions
        )

        attachments.append(
            EmailAttachment(
                filename=filename,
                content_type=content_type,
                size_bytes=size_bytes,
                sha256=sha256,
                extension=extension,
                detected_extensions=detected_extensions,
                has_double_extension=has_double_extension,
                is_suspicious_type=is_suspicious,
            )
        )

    return attachments
