import { list } from "@vercel/blob";

export default async function handler(request, response) {
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET");
    return response.status(405).json({ detail: "Método no permitido" });
  }

  try {
    const result = await list({
      prefix: "uploads/",
      limit: 1000,
      mode: "expanded"
    });

    const files = result.blobs.map((blob) => ({
      filename: blob.pathname.replace(/^uploads\//, ""),
      pathname: blob.pathname,
      size_bytes: blob.size,
      modified_at: blob.uploadedAt,
      content_type: blob.contentType,
      url: blob.url,
      download_url: blob.downloadUrl || `${blob.url}?download=1`,
      storage: "blob",
      is_text: false
    }));

    return response.status(200).json({
      ok: true,
      count: files.length,
      has_more: result.hasMore,
      cursor: result.cursor || null,
      files
    });
  } catch (error) {
    console.error("Error al listar Vercel Blob:", error);

    return response.status(500).json({
      detail: error instanceof Error
        ? error.message
        : "No fue posible listar los archivos de Vercel Blob"
    });
  }
}
