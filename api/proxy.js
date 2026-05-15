const PROXY_API_KEY = process.env.PROXY_API_KEY;

const BLOCKED_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "metadata.google.internal"
]);

function isPrivateOrLocalHostname(hostname) {
  const host = hostname.toLowerCase();

  if (BLOCKED_HOSTS.has(host)) return true;
  if (host.endsWith(".local")) return true;
  if (host.endsWith(".localhost")) return true;

  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const [a, b] = host.split(".").map(Number);

    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }

  return false;
}

export default async function handler(req, res) {
  try {
    if (!PROXY_API_KEY) {
      return res.status(500).json({
        error: "Missing PROXY_API_KEY on the server."
      });
    }

    const clientKey = req.headers["x-proxy-key"];

    if (clientKey !== PROXY_API_KEY) {
      return res.status(401).json({
        error: "Unauthorized. Missing or incorrect proxy key."
      });
    }

    const { url } = req.query;

    if (!url || typeof url !== "string") {
      return res.status(400).json({
        error: "Missing url parameter.",
        example: "/api/proxy?url=https://example.com"
      });
    }

    let targetUrl;

    try {
      targetUrl = new URL(url);
    } catch {
      return res.status(400).json({
        error: "Invalid URL."
      });
    }

    if (!["http:", "https:"].includes(targetUrl.protocol)) {
      return res.status(400).json({
        error: "Only HTTP and HTTPS URLs are allowed."
      });
    }

    if (isPrivateOrLocalHostname(targetUrl.hostname)) {
      return res.status(403).json({
        error: "Private, local, and internal hosts are blocked."
      });
    }

    const response = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: {
        "user-agent": "personal-vercel-proxy"
      },
      body: ["GET", "HEAD"].includes(req.method)
        ? undefined
        : JSON.stringify(req.body || {})
    });

    const contentType = response.headers.get("content-type") || "text/plain";

    res.status(response.status);
    res.setHeader("content-type", contentType);
    res.setHeader("access-control-allow-origin", "*");
    res.setHeader("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    res.setHeader("access-control-allow-headers", "content-type,x-proxy-key");

    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }

    const text = await response.text();
    return res.send(text);
  } catch (error) {
    return res.status(500).json({
      error: "Proxy failed.",
      message: error.message
    });
  }
}
