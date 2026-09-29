export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }
  try {
    const { put } = await import("@vercel/blob");
    const body = req.body || {};
    const filename = String(body.filename || "upload").slice(0, 200);
    const contentType = String(body.contentType || "application/octet-stream");
    const dataBase64 = String(body.dataBase64 || "");
    if (!dataBase64) {
      res.status(400).json({ error: "No file data provided." });
      return;
    }
    const buffer = Buffer.from(dataBase64, "base64");
    if (buffer.length > 4 * 1024 * 1024) {
      res.status(400).json({ error: "File too large (max 4MB)." });
      return;
    }
    const blob = await put(filename, buffer, { access: "public", contentType, addRandomSuffix: true });
    res.status(200).json({ url: blob.url });
  } catch (e) {
    res.status(502).json({ error: "Upload failed." });
  }
}