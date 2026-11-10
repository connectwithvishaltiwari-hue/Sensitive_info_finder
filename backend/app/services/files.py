"""Extract plain text from uploaded files. Files are processed in memory and
never written to disk."""
from __future__ import annotations
import io

ALLOWED_TEXT = {".txt", ".md", ".csv", ".log", ".json"}
MAX_PDF_PAGES = 200


class FileError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def extract_text(filename: str, data: bytes) -> str:
    name = (filename or "").lower()
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in ALLOWED_TEXT:
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")
    if ext == ".pdf":
        if not data.startswith(b"%PDF"):
            raise FileError("File content is not a valid PDF", 400)
        from pypdf import PdfReader
        try:
            reader = PdfReader(io.BytesIO(data))
            if reader.is_encrypted:
                raise FileError("Encrypted PDFs are not supported", 400)
            pages = reader.pages[:MAX_PDF_PAGES]
            return "\n".join((p.extract_text() or "") for p in pages)
        except FileError:
            raise
        except Exception:
            raise FileError("Could not read this PDF", 400) from None
    if ext == ".docx":
        if not data.startswith(b"PK"):
            raise FileError("File content is not a valid DOCX", 400)
        import docx
        try:
            d = docx.Document(io.BytesIO(data))
            lines = [p.text for p in d.paragraphs]
            for t in d.tables:
                for row in t.rows:
                    lines.append(" | ".join(c.text for c in row.cells))
            return "\n".join(lines)
        except Exception:
            raise FileError("Could not read this DOCX", 400) from None
    raise FileError("Unsupported file type. Use .txt, .md, .csv, .log, .json, .pdf or .docx", 415)
