from __future__ import annotations

import unicodedata
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_AUTHOR = "DarekDGB"
EXPECTED_REVIEWER = "Independent review"
CORE_PROPERTIES = "docProps/core.xml"
DOCUMENT_XML = "word/document.xml"
KNOWN_REVIEW = (
    ROOT
    / "docs"
    / "RED_TEAM"
    / "ADAMANTINEOS_MILESTONE_18_FINAL_CLOSURE_REVIEW.docx"
)
KNOWN_REVIEW_MARKDOWN = (
    ROOT
    / "docs"
    / "RED_TEAM"
    / "ADAMANTINEOS_MILESTONE_18_FINAL_CLOSURE_REVIEW.md"
)
NAMESPACES = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}
TEXT_MEMBER_SUFFIXES = (".xml", ".rels")


def _require_visible_value(document: ET.Element, label: str, value: str) -> None:
    text_nodes = [
        node.text or ""
        for node in document.findall(".//w:t", namespaces=NAMESPACES)
    ]
    indexes = [index for index, text in enumerate(text_nodes) if text == label]
    assert len(indexes) == 1
    index = indexes[0]
    assert index + 1 < len(text_nodes)
    assert text_nodes[index + 1] == value


def test_v49j_all_docx_core_attribution_is_darekdgb() -> None:
    docx_files = tuple(sorted(ROOT.rglob("*.docx")))

    assert KNOWN_REVIEW in docx_files

    for docx_path in docx_files:
        relative_path = docx_path.relative_to(ROOT)
        with zipfile.ZipFile(docx_path) as archive:
            assert archive.testzip() is None, f"{relative_path}: DOCX CRC failure"
            assert archive.namelist().count(CORE_PROPERTIES) == 1, (
                f"{relative_path}: expected one {CORE_PROPERTIES}"
            )

            for member in archive.infolist():
                if member.is_dir() or not member.filename.endswith(
                    TEXT_MEMBER_SUFFIXES
                ):
                    continue
                payload = archive.read(member)
                try:
                    text = payload.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    raise AssertionError(
                        f"{relative_path}:{member.filename}: invalid UTF-8"
                    ) from error
                if not text.isascii():
                    raise AssertionError(
                        f"{relative_path}:{member.filename}: non-ASCII text"
                    )
                if text != unicodedata.normalize("NFC", text):
                    raise AssertionError(
                        f"{relative_path}:{member.filename}: non-NFC text"
                    )
                if "\x00" in text or "\r" in text:
                    raise AssertionError(
                        f"{relative_path}:{member.filename}: unsafe text control"
                    )

            core = ET.fromstring(archive.read(CORE_PROPERTIES))
            if docx_path == KNOWN_REVIEW:
                document = ET.fromstring(archive.read(DOCUMENT_XML))
                _require_visible_value(
                    document,
                    "Author attribution",
                    EXPECTED_AUTHOR,
                )
                _require_visible_value(
                    document,
                    "Reviewer",
                    EXPECTED_REVIEWER,
                )

        creator = core.findtext("dc:creator", namespaces=NAMESPACES)
        last_modified_by = core.findtext("cp:lastModifiedBy", namespaces=NAMESPACES)

        if creator != EXPECTED_AUTHOR:
            raise AssertionError(
                f"{relative_path}: creator must equal {EXPECTED_AUTHOR}"
            )
        if last_modified_by != EXPECTED_AUTHOR:
            raise AssertionError(
                f"{relative_path}: lastModifiedBy must equal {EXPECTED_AUTHOR}"
            )


def test_v49m_closure_review_markdown_is_ascii_safe_and_darekdgb_only() -> None:
    payload = KNOWN_REVIEW_MARKDOWN.read_bytes()
    text = payload.decode("utf-8", errors="strict")

    assert payload.endswith(b"\n")
    assert not payload.startswith(b"\xef\xbb\xbf")
    assert text.isascii()
    assert text == unicodedata.normalize("NFC", text)
    assert "\x00" not in text
    assert "\r" not in text
    assert text.count(f"| Author attribution | {EXPECTED_AUTHOR} |") == 1
    assert text.count(f"| Reviewer | {EXPECTED_REVIEWER} |") == 1
