from __future__ import annotations

from pathlib import Path

import pytest

from phishlab.models.email import NormalizedEmail
from phishlab.parser.eml_parser import parse_eml_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def simple_email() -> NormalizedEmail:
    return parse_eml_file(FIXTURES_DIR / "simple.eml")


@pytest.fixture
def multipart_email() -> NormalizedEmail:
    return parse_eml_file(FIXTURES_DIR / "multipart.eml")


@pytest.fixture
def malformed_email() -> NormalizedEmail:
    return parse_eml_file(FIXTURES_DIR / "malformed.eml")


@pytest.fixture
def email_with_attachments() -> NormalizedEmail:
    return parse_eml_file(FIXTURES_DIR / "with_attachments.eml")


@pytest.fixture
def phishing_links_email() -> NormalizedEmail:
    return parse_eml_file(FIXTURES_DIR / "phishing_links.eml")


@pytest.fixture
def missing_headers_email() -> NormalizedEmail:
    return parse_eml_file(FIXTURES_DIR / "missing_headers.eml")
