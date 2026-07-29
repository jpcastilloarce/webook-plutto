from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
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


# =========================================================
# RUTAS DEL PROYECTO
# =========================================================

# webhook.py está dentro de /api.
# parent = /api
# parent.parent = raíz del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent

# Carpeta donde estará el frontend.
PUBLIC_DIR = BASE_DIR / "public"

# En Vercel solamente /tmp permite escritura.
# IMPORTANTE: su contenido es temporal y puede desaparecer.
BACKUP_DIR = Path("/tmp/backups")

BACKUP_DIR.mkdir(parents=True, exist_ok=True)


# =========================================================
# MODELOS
# =========================================================

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


# =========================================================
# FUNCIONES AUXILIARES
# =========================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sanitize_filename(filename: str) -> str:
    """
    Limpia el nombre para evitar rutas peligrosas como:

    ../../archivo.txt
    """

    filename = Path(filename).name.strip()

    # Reemplaza caracteres no permitidos por guion bajo.
    filename = re.sub(
        r"[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ._-]",
        "_",
        filename,
    )

    # Evita nombres ocultos, ".", ".." o nombres vacíos.
    filename = filename.lstrip(".")

    if not filename:
        filename = f"file_{uuid.uuid4().hex}"

    # Limita el largo del nombre.
    return filename[:200]


def create_unique_path(filename: str) -> Path:
    """
    Evita sobrescribir archivos.

    Si ya existe:

    ejemplo.txt

    genera algo como:

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
        f"{file_path.stem}_{timestamp}_{unique_id}"
        f"{file_path.suffix}"
    )

    return BACKUP_DIR / new_filename


def calculate_sha256(file_path: Path) -> str:
    """
    Calcula el hash SHA-256 de un archivo.
    """

    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


# =========================================================
# ENDPOINT PARA SUBIR ARCHIVOS
# =========================================================

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
                detail=(
                    f"No se pudo guardar el archivo "
                    f"{original_name}: {str(exc)}"
                ),
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
                "download_url": f"/files/{destination.name}",
            }
        )

    return {
        "ok": True,
        "saved_count": len(saved_files),
        "files": saved_files,
    }


# =========================================================
# ENDPOINT PARA GUARDAR TEXTO
# =========================================================

@app.post("/text")
def save_text(payload: TextFileRequest):
    """
    Recibe JSON con un texto y lo guarda como archivo TXT.

    Ejemplo:

    {
        "filename": "ejemplo.txt",
        "text": "Contenido del archivo"
    }
    """

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
        destination.write_text(
            payload.text,
            encoding="utf-8",
        )

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
        "download_url": f"/files/{destination.name}",
    }


# =========================================================
# ENDPOINT PARA LISTAR ARCHIVOS
# =========================================================

@app.get("/files")
def list_files():
    """
    Lista todos los archivos guardados en /tmp/backups.
    """

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
            detail=f"No se pudieron listar los archivos: {str(exc)}",
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
            }
        )

    return {
        "ok": True,
        "directory": str(BACKUP_DIR),
        "count": len(files),
        "files": files,
    }


# =========================================================
# ENDPOINT PARA DESCARGAR ARCHIVOS
# =========================================================

@app.get("/files/{filename}")
def download_file(filename: str):
    """
    Descarga un archivo guardado.
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


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": utc_now().isoformat(),
        "backup_directory": str(BACKUP_DIR),
        "public_directory": str(PUBLIC_DIR),
        "public_directory_exists": PUBLIC_DIR.exists(),
    }


# =========================================================
# FRONTEND ESTÁTICO
# =========================================================
#
# Este montaje debe quedar al final, después de todos los
# endpoints de la API.
#
# De esta forma:
#
# GET  /              -> public/index.html
# GET  /style.css     -> public/style.css
# GET  /app.js        -> public/app.js
# POST /upload        -> endpoint FastAPI
# POST /text          -> endpoint FastAPI
# GET  /files         -> endpoint FastAPI
# GET  /health        -> endpoint FastAPI
#

if PUBLIC_DIR.exists():
    app.mount(
        "/",
        StaticFiles(
            directory=str(PUBLIC_DIR),
            html=True,
        ),
        name="public",
    )
