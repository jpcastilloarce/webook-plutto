import { handleUpload } from "@vercel/blob/client";

export default async function handler(request, response) {
  if (request.method !== "POST") {
    return response.status(405).json({
      detail: "Método no permitido"
    });
  }

  try {
    const body = request.body;

    const jsonResponse = await handleUpload({
      request,
      body,

      onBeforeGenerateToken: async (
        pathname,
        clientPayload,
        multipart
      ) => {
        return {
          allowedContentTypes: [
            "image/*",
            "application/pdf",
            "application/zip",
            "application/x-zip-compressed",
            "audio/*",
            "video/*",
            "application/octet-stream"
          ],

          maximumSizeInBytes: 500 * 1024 * 1024,

          addRandomSuffix: true,

          tokenPayload: JSON.stringify({
            originalName: pathname
          })
        };
      },

      onUploadCompleted: async ({ blob, tokenPayload }) => {
        console.log("Archivo subido a Blob:", {
          blob,
          tokenPayload
        });
      }
    });

    return response.status(200).json(jsonResponse);
  } catch (error) {
    console.error("Error de Blob:", error);

    return response.status(400).json({
      detail: error instanceof Error
        ? error.message
        : "No fue posible autorizar la subida"
    });
  }
}
