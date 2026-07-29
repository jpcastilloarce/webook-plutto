# File Backup con Vercel Blob

## Qué guarda cada almacenamiento

- Archivos de texto: `/tmp/backups` mediante FastAPI.
- Imágenes, PDF, ZIP, Office, audio, video y otros binarios: Vercel Blob directamente desde el navegador.

## Configuración

1. En Vercel abre **Storage** y crea/conecta un Blob Store público.
2. Confirma que el proyecto tenga `BLOB_READ_WRITE_TOKEN`.
3. Sube estos archivos al repositorio y vuelve a desplegar.
4. No copies el token en `index.html`.

## Desarrollo local

```bash
npm install
pip install -r requirements.txt
vercel dev
```

Para desarrollo local, descarga las variables:

```bash
vercel env pull .env.local
```

## Endpoints

- `POST /upload`: solo archivos de texto.
- `POST /text`: guarda texto escrito.
- `GET /files`: lista textos en `/tmp`.
- `GET /files/{filename}`: abre/descarga un texto.
- `POST /api/blob-upload`: autoriza Client Uploads.
- `GET /api/blobs`: lista archivos del Blob Store.
- `GET /health`: estado de FastAPI.

## Nota

El Blob Store está configurado como público. Cualquier persona que conozca la URL de un archivo puede acceder a él. Para documentos sensibles se necesita Blob privado y autenticación.
