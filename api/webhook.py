from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from pathlib import Path
from typing import List
import hashlib
import re
import uuid


app = FastAPI(
    title="File Backup API",
    version="1.1.0",
    description="API para guardar textos temporalmente y usar Vercel Blob para archivos binarios",
)


BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_DIR = BASE_DIR / "public"

# En Vercel solo /tmp permite escritura. Su contenido es temporal.
BACKUP_DIR = Path("/tmp/backups")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".csv", ".log", ".xml", ".html", ".htm",
    ".css", ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".sql",
    ".yaml", ".yml", ".ini", ".conf", ".properties", ".sh", ".bat",
    ".ps1", ".c", ".cpp", ".h", ".hpp", ".go", ".rs", ".php", ".rb",
}


class TextFileRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        description="Contenido que se guardará dentro del archivo",
    )
    filename: str | None = Field(
        default=None,
        description="Nombre opcional del archivo, con o sin extensión .txt",
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sanitize_filename(filename: str) -> str:
    filename = Path(filename).name.strip()
    filename = re.sub(
        r"[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ._-]",
        "_",
        filename,
    )
    filename = filename.lstrip(".")

    if not filename:
        filename = f"file_{uuid.uuid4().hex}"

    return filename[:200]


def is_text_filename(filename: str) -> bool:
    return Path(filename).suffix.lower() in TEXT_EXTENSIONS


def create_unique_path(filename: str) -> Path:
    filename = sanitize_filename(filename)
    destination = BACKUP_DIR / filename

    if not destination.exists():
        return destination

    file_path = Path(filename)
    timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:6]

    return BACKUP_DIR / (
        f"{file_path.stem}_{timestamp}_{unique_id}{file_path.suffix}"
    )


def calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


@app.post("/upload")
async def upload_text_files(
    files: List[UploadFile] = File(...),
):
    """
    Guarda únicamente archivos de texto en /tmp.

    Imágenes, PDF, ZIP, videos y demás archivos deben subirse
    directamente desde el navegador hacia Vercel Blob.
    """
    saved_files = []

    for uploaded_file in files:
        original_name = uploaded_file.filename or "unnamed_file"

        if not is_text_filename(original_name):
            await uploaded_file.close()
            raise HTTPException(
                status_code=415,
                detail=(
                    f"{original_name} no es un archivo de texto. "
                    "Debe subirse mediante Vercel Blob."
                ),
            )

        destination = create_unique_path(original_name)
        total_bytes = 0

        try:
            with destination.open("wb") as output_file:
                while chunk := await uploaded_file.read(1024 * 1024):
                    output_file.write(chunk)
                    total_bytes += len(chunk)

        except Exception as exc:
            if destination.exists():
                destination.unlink()

            raise HTTPException(
                status_code=500,
                detail=f"No se pudo guardar {original_name}: {str(exc)}",
            ) from exc

        finally:
            await uploaded_file.close()

        saved_files.append(
            {
                "original_filename": original_name,
                "stored_filename": destination.name,
                "content_type": uploaded_file.content_type,
                "size_bytes": total_bytes,
                "sha256": calculate_sha256(destination),
                "storage": "tmp",
                "created_at": utc_now().isoformat(),
                "download_url": f"/files/{destination.name}",
            }
        )

    return {
        "ok": True,
        "saved_count": len(saved_files),
        "files": saved_files,
    }


@app.post("/text")
def save_text(payload: TextFileRequest):
    if payload.filename:
        filename = sanitize_filename(payload.filename)

        if not filename.lower().endswith(".txt"):
            filename += ".txt"
    else:
        timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:6]
        filename = f"text_{timestamp}_{unique_id}.txt"

    destination = create_unique_path(filename)

    try:
        destination.write_text(payload.text, encoding="utf-8")
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo guardar el texto: {str(exc)}",
        ) from exc

    return {
        "ok": True,
        "stored_filename": destination.name,
        "size_bytes": destination.stat().st_size,
        "characters": len(payload.text),
        "sha256": calculate_sha256(destination),
        "storage": "tmp",
        "created_at": utc_now().isoformat(),
        "download_url": f"/files/{destination.name}",
    }


@app.get("/files")
def list_files():
    files = []

    try:
        file_paths = sorted(
            BACKUP_DIR.iterdir(),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudieron listar los textos: {str(exc)}",
        ) from exc

    for file_path in file_paths:
        if not file_path.is_file():
            continue

        stat = file_path.stat()

        files.append(
            {
                "filename": file_path.name,
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(
                    stat.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
                "download_url": f"/files/{file_path.name}",
                "storage": "tmp",
                "is_text": True,
            }
        )

    return {
        "ok": True,
        "directory": str(BACKUP_DIR),
        "count": len(files),
        "files": files,
    }


@app.get("/files/{filename}")
def download_file(filename: str):
    safe_filename = sanitize_filename(filename)
    file_path = BACKUP_DIR / safe_filename

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    # text/plain permite que fetch().text() lo lea correctamente.
    media_type = "text/plain; charset=utf-8" if is_text_filename(file_path.name) else "application/octet-stream"

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type=media_type,
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": utc_now().isoformat(),
        "backup_directory": str(BACKUP_DIR),
        "public_directory": str(PUBLIC_DIR),
        "blob_mode": "client-upload",
    }
