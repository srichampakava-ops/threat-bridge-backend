import pdfplumber
from docx import Document
import io

def extract_text(file_bytes: bytes, filename: str) -> str:
    extension = filename.lower().split(".")[-1]

    if extension == "pdf":
        text = ""
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""
        return text

    elif extension == "docx":
        doc = Document(io.BytesIO(file_bytes))
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text

    elif extension == "txt":
        return file_bytes.decode("utf-8")

    else:
        raise ValueError(f"Unsupported file type: {extension}")