import { handleUpload } from "@vercel/blob/client";

const TEXT_EXTENSIONS = new Set([
  "txt", "md", "json", "csv", "log", "xml", "html", "htm",
  "css", "js", "jsx", "ts", "tsx", "py", "java", "sql",
  "yaml", "yml", "ini", "conf", "properties", "sh", "bat",
  "ps1", "c", "cpp", "h", "hpp", "go", "rs", "php", "rb"
]);

function extensionOf(pathname = "") {
  const cleanName = pathname.split("/").pop() || "";
  const dot = cleanName.lastIndexOf(".");
  return dot >= 0 ? cleanName.slice(dot + 1).toLowerCase() : "";
}

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return response.status(405).json({ detail: "Método no permitido" });
  }

  try {
    const result = await handleUpload({
      request,
      body: request.body,

      onBeforeGenerateToken: async (pathname) => {
        const extension = extensionOf(pathname);

        if (TEXT_EXTENSIONS.has(extension)) {
          throw new Error(
            "Los archivos de texto deben guardarse mediante el endpoint /upload."
          );
        }

        if (!pathname.startsWith("uploads/")) {
          throw new Error("Ruta de archivo no permitida.");
        }

        return {
          allowedContentTypes: [
            "image/*",
            "audio/*",
            "video/*",
            "application/pdf",
            "application/zip",
            "application/x-zip-compressed",
            "application/x-rar-compressed",
            "application/vnd.rar",
            "application/x-7z-compressed",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/octet-stream"
          ],
          maximumSizeInBytes: 500 * 1024 * 1024,
          addRandomSuffix: true,
          tokenPayload: JSON.stringify({
            originalPathname: pathname,
            uploadedAt: new Date().toISOString()
          })
        };
      },

      onUploadCompleted: async ({ blob, tokenPayload }) => {
        console.log("Subida completada en Vercel Blob", {
          pathname: blob.pathname,
          url: blob.url,
          tokenPayload
        });
      }
    });

    return response.status(200).json(result);
  } catch (error) {
    console.error("Error al autorizar Vercel Blob:", error);

    return response.status(400).json({
      detail: error instanceof Error
        ? error.message
        : "No fue posible autorizar la subida"
    });
  }
}
