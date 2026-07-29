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
    version="1.0.0",
    description="API para respaldar archivos y textos en el servidor",
)

# En Vercel solamente /tmp permite escritura.
# IMPORTANTE: su contenido es temporal y puede desaparecer.
BACKUP_DIR = Path("/tmp/backups")

# Para un servidor propio puedes usar, por ejemplo:
# BACKUP_DIR = Path("./backups")
# BACKUP_DIR = Path("/var/lib/my-api/backups")

BACKUP_DIR.mkdir(parents=True, exist_ok=True)


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
    """
    Limpia el nombre para evitar rutas como:
    ../../archivo.txt
    """
    filename = Path(filename).name.strip()

    # Reemplaza caracteres extraños por guion bajo.
    filename = re.sub(r"[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ._-]", "_", filename)

    # Evita nombres vacíos, ocultos o rutas especiales.
    filename = filename.lstrip(".")

    if not filename:
        filename = f"file_{uuid.uuid4().hex}"

    # Limita el largo del nombre.
    return filename[:200]


def create_unique_path(filename: str) -> Path:
    """
    Si el archivo ya existe, genera otro nombre para no sobrescribirlo.

    ejemplo.txt
    ejemplo_20260729_104700_a1b2c3.txt
    """
    filename = sanitize_filename(filename)
    destination = BACKUP_DIR / filename

    if not destination.exists():
        return destination

    file_path = Path(filename)
    timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:6]

    new_filename = (
        f"{file_path.stem}_{timestamp}_{unique_id}{file_path.suffix}"
    )

    return BACKUP_DIR / new_filename


def calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


@app.post("/upload")
async def upload_files(
    files: List[UploadFile] = File(...),
):
    """
    Recibe uno o varios archivos mediante multipart/form-data.
    """
    saved_files = []

    for uploaded_file in files:
        original_name = uploaded_file.filename or "unnamed_file"
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
                "path": str(destination),
                "created_at": utc_now().isoformat(),
            }
        )

    return {
        "ok": True,
        "saved_count": len(saved_files),
        "files": saved_files,
    }


@app.post("/text")
def save_text(payload: TextFileRequest):
    """
    Recibe JSON con un texto grande y lo guarda como archivo .txt.
    """
    if payload.filename:
        filename = sanitize_filename(payload.filename)

        if not filename.lower().endswith(".txt"):
            filename += ".txt"
    else:
        timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
        filename = f"text_{timestamp}_{uuid.uuid4().hex[:6]}.txt"

    destination = create_unique_path(filename)

    try:
        destination.write_text(payload.text, encoding="utf-8")
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo guardar el texto: {str(exc)}",
        ) from exc

    size_bytes = destination.stat().st_size

    return {
        "ok": True,
        "stored_filename": destination.name,
        "size_bytes": size_bytes,
        "characters": len(payload.text),
        "sha256": calculate_sha256(destination),
        "path": str(destination),
        "created_at": utc_now().isoformat(),
    }


@app.get("/files")
def list_files():
    """
    Lista los archivos respaldados.
    """
    files = []

    for file_path in sorted(
        BACKUP_DIR.iterdir(),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    ):
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
    """
    Descarga un archivo respaldado.
    """
    safe_filename = sanitize_filename(filename)
    file_path = BACKUP_DIR / safe_filename

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Archivo no encontrado",
        )

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="application/octet-stream",
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": utc_now().isoformat(),
        "backup_directory": str(BACKUP_DIR),
    }
