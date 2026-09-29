export const config = { runtime: "edge" };

export default async function handler(request) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed." }), { status: 405 });
  }
  try {
    const { put } = await import("@vercel/blob");
    const form = await request.formData();
    const file = form.get("file");
    if (!file || typeof file === "string") {
      return new Response(JSON.stringify({ error: "No file provided." }), { status: 400 });
    }
    if (file.size > 4 * 1024 * 1024) {
      return new Response(JSON.stringify({ error: "File too large (max 4MB)." }), { status: 400 });
    }
    const blob = await put(file.name, file, { access: "public", addRandomSuffix: true });
    return new Response(JSON.stringify({ url: blob.url }), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: "Upload failed." }), { status: 502 });
  }
}