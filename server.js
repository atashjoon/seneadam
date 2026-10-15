
import http from "node:http";
import { randomBytes } from "node:crypto";

const PORT = Number(process.env.PORT || 3000);
const MAX_BODY = 1024 * 1024;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function send(res, status, data) {
  res.writeHead(status, {
    ...CORS,
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

function randomHex(bytes = 8) {
  return randomBytes(bytes).toString("hex");
}

function required(value, name) {
  const result = String(value ?? "").trim();
  if (!result) throw new Error(`${name} is required`);
  return result;
}

function validSecret(value) {
  const length = Buffer.byteLength(value, "utf8");
  return length >= 16 && length <= 256;
}

async function readBody(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > MAX_BODY) {
      throw new Error("Request body is too large");
    }
  }
  return JSON.parse(body);
}

async function github(url, token, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Trendify-Nexus-Installer",
      ...(options.headers || {}),
    },
    signal: AbortSignal.timeout(30000),
  });
}

async function githubJson(url, token, options = {}) {
  const response = await github(url, token, options);
  const text = await response.text();

  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      `GitHub API ${response.status}: ${
        data.message || text || "Request failed"
      }`
    );
  }

  return data;
}

async function cloudflare(path, token, options = {}) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4${path}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(options.headers || {}),
      },
      signal: AbortSignal.timeout(30000),
    }
  );

  const text = await response.text();
  let data;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Cloudflare returned invalid JSON: ${text}`);
  }

  if (!response.ok || data.success !== true) {
    const errors = (data.errors || [])
      .map(x => x.message || JSON.stringify(x))
      .join("; ");

    throw new Error(
      `Cloudflare API ${response.status}: ${errors || text}`
    );
  }

  return data.result;
}

function base64UTF8(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

async function putRepoFile(owner, repo, path, content, token) {
  const encodedPath = path
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  const url =
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodedPath}`;

  let sha;

  const existing = await github(url, token);

  if (existing.ok) {
    sha = (await existing.json()).sha;
  } else if (existing.status !== 404) {
    throw new Error(
      `Cannot inspect destination file ${path}: ${await existing.text()}`
    );
  }

  const response = await github(url, token, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: `Installer: add ${path}`,
      content: base64UTF8(content),
      ...(sha ? { sha } : {}),
    }),
  });

  if (!response.ok) {
    throw new Error(
      `Cannot upload ${path}: ${await response.text()}`
    );
  }
}

/* =========================================================
   AUTHENTICATED TCP RELAY SOURCE
========================================================= */

const RELAY_SOURCE = String.raw`
import net from "node:net";
import { timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 443);
const SECRET = String(process.env.RELAY_SECRET || "");
const expectedSecret = Buffer.from(SECRET, "utf8");

if (
  !Number.isInteger(PORT) || PORT < 1 || PORT > 65535 ||
  expectedSecret.length < 16 || expectedSecret.length > 256
) {
  console.error("Invalid PORT or RELAY_SECRET");
  process.exit(1);
}

const server = net.createServer(client => {
  client.setNoDelay(true);

  let remote = null;
  let buffer = Buffer.alloc(0);
  let stage = "secretLength";
  let secretLength = 0;
  let hostLength = 0;
  let finished = false;
  let connectTimer = null;

  const headerTimer = setTimeout(() => {
    if (stage !== "connected") reject("Handshake timeout");
  }, 10000);

  function reject(reason) {
    if (finished) return;
    finished = true;
    clearTimeout(headerTimer);
    clearTimeout(connectTimer);
    console.log("RELAY REJECT:", reason);
    client.destroy();
    remote?.destroy();
  }

  function onData(chunk) {
    if (finished) return;
    buffer = Buffer.concat([buffer, chunk]);

    while (true) {
      if (stage === "secretLength") {
        if (buffer.length < 2) return;
        secretLength = buffer.readUInt16BE(0);
        buffer = buffer.subarray(2);

        if (secretLength < 16 || secretLength > 256) {
          return reject("Invalid secret length");
        }
        stage = "secret";
      }

      if (stage === "secret") {
        if (buffer.length < secretLength) return;
        const received = buffer.subarray(0, secretLength);
        buffer = buffer.subarray(secretLength);

        if (
          received.length !== expectedSecret.length ||
          !timingSafeEqual(received, expectedSecret)
        ) {
          return reject("Authentication failed");
        }
        stage = "hostLength";
      }

      if (stage === "hostLength") {
        if (buffer.length < 2) return;
        hostLength = buffer.readUInt16BE(0);
        buffer = buffer.subarray(2);

        if (hostLength < 1 || hostLength > 255) {
          return reject("Invalid host length");
        }
        stage = "target";
      }

      if (stage === "target") {
        if (buffer.length < hostLength + 2) return;

        const host = buffer.subarray(0, hostLength).toString("utf8");
        const port = buffer.readUInt16BE(hostLength);
        const initialPayload = buffer.subarray(hostLength + 2);
        buffer = Buffer.alloc(0);
        stage = "connecting";

        if (!host || /[\0\r\n]/.test(host) || port < 1) {
          return reject("Invalid destination");
        }

        clearTimeout(headerTimer);
        client.pause();
        client.removeListener("data", onData);

        try {
          remote = net.connect({ host, port });
          remote.setNoDelay(true);

          let acknowledged = false;

          connectTimer = setTimeout(() => {
            if (!acknowledged && !client.destroyed) {
              client.end(Buffer.from([1]));
              remote?.destroy();
            }
          }, 10000);

          remote.once("connect", () => {
            if (finished) return remote.destroy();

            acknowledged = true;
            clearTimeout(connectTimer);
            stage = "connected";

            if (initialPayload.length) remote.write(initialPayload);

            // 0 = connected successfully; 1 = connection failed.
            client.write(Buffer.from([0]));

            client.pipe(remote);
            remote.pipe(client);
            client.resume();
          });

          remote.on("error", err => {
            console.log("REMOTE ERROR:", err.message);
            clearTimeout(connectTimer);

            if (!acknowledged && !client.destroyed) {
              client.end(Buffer.from([1]));
            } else {
              client.destroy();
            }
          });

          remote.on("close", () => {
            clearTimeout(connectTimer);
            if (!client.destroyed) client.destroy();
          });
        } catch (err) {
          reject(err.message);
        }
        return;
      }

      return;
    }
  }

  client.on("data", onData);
  client.on("error", err => {
    console.log("CLIENT ERROR:", err.message);
    remote?.destroy();
  });
  client.on("close", () => {
    finished = true;
    clearTimeout(headerTimer);
    clearTimeout(connectTimer);
    remote?.destroy();
  });
});

server.on("error", err => console.error("RELAY SERVER ERROR:", err));

server.listen(PORT, "0.0.0.0", () => {
  console.log("Authenticated TCP Relay listening on", PORT);
});
`;

/* =========================================================
   CLOUDFLARE GATEWAY WORKER SOURCE
========================================================= */

const GATEWAY_SOURCE = String.raw`
import { connect } from "cloudflare:sockets";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function uuidFromBytes(bytes) {
  const h = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  return h.slice(0,8) + "-" + h.slice(8,12) + "-" +
    h.slice(12,16) + "-" + h.slice(16,20) + "-" + h.slice(20,32);
}

function parseVless(bytes) {
  if (bytes.length < 18) return null;

  const version = bytes[0];
  if (version !== 0) throw new Error("Unsupported VLESS version");

  const uuid = uuidFromBytes(bytes.subarray(1, 17));
  const optionsLength = bytes[17];
  let i = 18 + optionsLength;

  if (bytes.length < i + 4) return null;

  const command = bytes[i++];
  if (command !== 1) throw new Error("Only TCP is supported");

  const port = (bytes[i++] << 8) | bytes[i++];
  const type = bytes[i++];
  let host = "";

  if (type === 1) {
    if (bytes.length < i + 4) return null;
    host = Array.from(bytes.subarray(i, i + 4)).join(".");
    i += 4;
  } else if (type === 2) {
    if (bytes.length < i + 1) return null;
    const length = bytes[i++];
    if (length < 1) throw new Error("Invalid domain length");
    if (bytes.length < i + length) return null;
    host = new TextDecoder().decode(bytes.subarray(i, i + length));
    i += length;
  } else if (type === 3) {
    if (bytes.length < i + 16) return null;
    const parts = [];
    for (let n = 0; n < 16; n += 2) {
      parts.push(((bytes[i+n] << 8) | bytes[i+n+1]).toString(16));
    }
    host = parts.join(":");
    i += 16;
  } else {
    throw new Error("Unsupported address type");
  }

  if (!host || !port) throw new Error("Invalid destination");
  return { version, uuid: uuid.toLowerCase(), host, port, offset: i };
}

async function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  throw new Error("Binary WebSocket messages are required");
}

async function authorize(env, uuid) {
  const base = String(env.NEXUS_API_URL || "").trim().replace(/\\/+$/, "");
  if (!base || !env.NEXUS_GATEWAY_SECRET || !env.GATEWAY_ID) {
    throw new Error("Backend authorization is not configured");
  }

  const url = new URL(base + "/api/internal/gateway/auth");
  url.searchParams.set("uuid", uuid);
  url.searchParams.set("gateway_id", String(env.GATEWAY_ID));

  const response = await fetch(url, {
    headers: {
      "X-Nexus-Gateway-Secret": env.NEXUS_GATEWAY_SECRET,
      "Accept": "application/json"
    },
    signal: AbortSignal.timeout(10000)
  });

  if (!response.ok) {
    throw new Error("Backend authorization returned HTTP " + response.status);
  }

  const data = await response.json();
  if (data.authorized !== true) throw new Error("UUID is not authorized");
  return data;
}

async function handleWebSocket(request, env) {
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return new Response("Expected WebSocket", {
      status: 426,
      headers: { "Upgrade": "websocket" }
    });
  }

  const relayHost = String(env.RELAY_HOST || "").trim();
  const relayPort = Number(env.RELAY_PORT || 0);
  const relaySecret = String(env.RELAY_SECRET || "");

  if (!relayHost || !Number.isInteger(relayPort) ||
      relayPort < 1 || relayPort > 65535 ||
      !env.NEXUS_API_URL || !env.NEXUS_GATEWAY_SECRET || !env.GATEWAY_ID) {
    return new Response("Gateway configuration is incomplete", { status: 503 });
  }

  const secretBytes = new TextEncoder().encode(relaySecret);
  if (secretBytes.length < 16 || secretBytes.length > 256) {
    return new Response("Invalid relay secret", { status: 503 });
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const ws = pair[1];
  ws.accept();
  ws.binaryType = "arraybuffer";

  let pending = new Uint8Array(0);
  let socket = null;
  let writer = null;
  let closed = false;
  let connected = false;
  let chain = Promise.resolve();

  function closeAll() {
    if (closed) return;
    closed = true;
    try { ws.close(); } catch {}
    try { writer?.close(); } catch {}
    try { socket?.close(); } catch {}
  }

  async function relayToClient(parsed, reader) {
    let ackPending = true;

    try {
      while (!closed) {
        const result = await reader.read();
        if (result.done) break;
        if (!result.value?.length) continue;

        let chunk = result.value;

        if (ackPending) {
          ackPending = false;
          if (chunk[0] !== 0) throw new Error("Relay rejected connection");

          if (ws.readyState === WebSocket.OPEN) {
            ws.send(new Uint8Array([parsed.version, 0]));
          }

          chunk = chunk.subarray(1);
        }

        if (chunk.length && ws.readyState === WebSocket.OPEN) ws.send(chunk);
      }
    } catch {
      closeAll();
    } finally {
      closeAll();
    }
  }

  async function onMessage(data) {
    const incoming = await toBytes(data);
    if (closed) return;

    if (connected) {
      await writer.write(incoming);
      return;
    }

    if (pending.length + incoming.length > 65536) {
      throw new Error("VLESS header is too large");
    }

    const merged = new Uint8Array(pending.length + incoming.length);
    merged.set(pending);
    merged.set(incoming, pending.length);
    pending = merged;

    const parsed = parseVless(pending);
    if (!parsed) return;

    await authorize(env, parsed.uuid);

    const hostBytes = new TextEncoder().encode(parsed.host);
    if (!hostBytes.length || hostBytes.length > 255) {
      throw new Error("Invalid destination hostname");
    }

    const payload = pending.subarray(parsed.offset);
    const frame = new Uint8Array(
      2 + secretBytes.length + 2 + hostBytes.length + 2 + payload.length
    );

    let p = 0;
    frame[p++] = secretBytes.length >> 8;
    frame[p++] = secretBytes.length & 255;
    frame.set(secretBytes, p);
    p += secretBytes.length;

    frame[p++] = hostBytes.length >> 8;
    frame[p++] = hostBytes.length & 255;
    frame.set(hostBytes, p);
    p += hostBytes.length;

    frame[p++] = parsed.port >> 8;
    frame[p++] = parsed.port & 255;
    frame.set(payload, p);

    socket = connect({ hostname: relayHost, port: relayPort });
    await socket.opened;
    if (closed) return socket.close();

    writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    await writer.write(frame);
    connected = true;
    pending = new Uint8Array(0);

    relayToClient(parsed, reader);
  }

  ws.addEventListener("message", event => {
    chain = chain.then(() => onMessage(event.data)).catch(() => closeAll());
  });
  ws.addEventListener("close", closeAll);
  ws.addEventListener("error", closeAll);

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    if (url.pathname === "/" || url.pathname === "/health") {
      return json({
        success: true,
        status: "online",
        gateway: "Trendify Nexus Gateway",
        gateway_id: env.GATEWAY_ID || "",
        region: env.GATEWAY_REGION || ""
      });
    }

    if (url.pathname === "/ws" || url.pathname.startsWith("/ws/")) {
      return handleWebSocket(request, env);
    }

    return new Response("Not Found", { status: 404 });
  }
};
`;

/* =========================================================
   CLOUDFLARE DEPLOYMENT
========================================================= */

async function deployGateway({
  accountId,
  token,
  workerName,
  gatewayId,
  region,
  backendUrl,
  gatewaySecret,
  relayHost,
  relayPort,
  relaySecret,
}) {
  const placements = {
    eu: "gcp:europe-west1",
    us: "gcp:us-east4",
    asia: "gcp:asia-east1",
  };

  if (!placements[region]) {
    throw new Error("Region must be eu, us or asia");
  }

  const metadata = {
    main_module: "index.js",
    compatibility_date: "2026-10-10",
    placement: {
      mode: "targeted",
      region: placements[region],
    },
    bindings: [
      { type: "plain_text", name: "GATEWAY_ID", text: String(gatewayId) },
      { type: "plain_text", name: "GATEWAY_REGION", text: region },
      { type: "plain_text", name: "NEXUS_API_URL", text: backendUrl },
      { type: "secret_text", name: "NEXUS_GATEWAY_SECRET", text: gatewaySecret },
      { type: "plain_text", name: "RELAY_HOST", text: relayHost },
      { type: "plain_text", name: "RELAY_PORT", text: String(relayPort) },
      { type: "secret_text", name: "RELAY_SECRET", text: relaySecret },
    ],
  };

  const form = new FormData();
  form.append(
    "metadata",
    new Blob([JSON.stringify(metadata)], { type: "application/json" })
  );
  form.append(
    "index.js",
    new Blob([GATEWAY_SOURCE], { type: "application/javascript+module" }),
    "index.js"
  );

  await cloudflare(
    `/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}`,
    token,
    { method: "PUT", body: form }
  );

  await cloudflare(
    `/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}/subdomain`,
    token,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true }),
    }
  );
}

/* =========================================================
   INSTALL ROUTE
========================================================= */

async function install(body) {
  const githubToken = required(body.githubToken, "GitHub token");
  const cloudflareToken = required(body.cloudflareToken, "Cloudflare token");
  const accountId = required(body.accountId, "Cloudflare Account ID");
  const backendUrl = required(body.backendUrl, "Backend URL").replace(/\/+$/, "");
  const gatewayId = required(body.gatewayId, "Gateway ID");
  const gatewaySecret = required(body.nexusGatewaySecret, "NEXUS_GATEWAY_SECRET");
  const relayHost = required(body.relayHost, "Railway TCP proxy host");
  const relayPort = Number(body.relayPort);
  const relaySecret = required(body.relaySecret, "RELAY_SECRET");
  const region = String(body.region || "eu").trim().toLowerCase();
  const sourceRepo = String(
    body.backendRepository || "Trendiify/trendify-nexus-backend"
  ).trim();

  if (!/^https:\/\/[^/]+/i.test(backendUrl)) {
    throw new Error("Backend URL must be a valid HTTPS URL");
  }
  if (!/^\d+$/.test(gatewayId)) {
    throw new Error("Gateway ID must be a numeric PostgreSQL ID");
  }
  if (!Number.isInteger(relayPort) || relayPort < 1 || relayPort > 65535) {
    throw new Error("Invalid Railway TCP proxy port");
  }
  if (!validSecret(relaySecret) || !validSecret(gatewaySecret)) {
    throw new Error("Both secrets must be 16-256 UTF-8 bytes");
  }
  if (!["eu", "us", "asia"].includes(region)) {
    throw new Error("Region must be eu, us or asia");
  }

  const sourceParts = sourceRepo.split("/");
  if (sourceParts.length !== 2 || sourceParts.some(x => !x)) {
    throw new Error("Backend repository must use owner/repo format");
  }

  const user = await githubJson("https://api.github.com/user", githubToken);
  const owner = user.login;

  const tokenResult = await cloudflare("/user/tokens/verify", cloudflareToken);
  if (tokenResult.status !== "active") {
    throw new Error("Cloudflare API token is not active");
  }

  const subdomainInfo = await cloudflare(
    `/accounts/${encodeURIComponent(accountId)}/workers/subdomain`,
    cloudflareToken
  );
  const subdomain = subdomainInfo?.subdomain || subdomainInfo?.name;
  if (!subdomain) {
    throw new Error("Activate workers.dev for this Cloudflare account first");
  }

  // Check backend reachability and gateway-secret validity before creating resources.
  const probe = new URL(backendUrl + "/api/internal/gateway/auth");
  probe.searchParams.set("uuid", "00000000-0000-4000-8000-000000000000");
  probe.searchParams.set("gateway_id", gatewayId);

  const probeResponse = await fetch(probe, {
    headers: { "X-Nexus-Gateway-Secret": gatewaySecret },
    signal: AbortSignal.timeout(15000),
  });

  if (probeResponse.status === 401 || probeResponse.status === 403) {
    throw new Error("NEXUS_GATEWAY_SECRET was rejected by the backend");
  }
  if (!probeResponse.ok) {
    throw new Error(
      `Backend authorization endpoint returned HTTP ${probeResponse.status}`
    );
  }

  // Read source repository and its default branch.
  const [sourceOwner, sourceName] = sourceParts;
  const sourceMeta = await githubJson(
    `https://api.github.com/repos/${encodeURIComponent(sourceOwner)}/${encodeURIComponent(sourceName)}`,
    githubToken
  );
  const branch = sourceMeta.default_branch || "main";

  const treeData = await githubJson(
    `https://api.github.com/repos/${encodeURIComponent(sourceOwner)}/${encodeURIComponent(sourceName)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    githubToken
  );

  if (treeData.truncated) {
    throw new Error("Source repository tree is too large; copy it manually instead");
  }

  const blocked =
    /(^|\/)(\.git|node_modules|coverage|\.wrangler)(\/|$)|(^|\/)\.env(?:\..*)?$|(^|\/)(\.DS_Store|npm-debug\.log)$/i;

  const files = (treeData.tree || []).filter(
    file => file.type === "blob" && !blocked.test(file.path)
  );

  if (!files.length) {
    throw new Error("No source files found in the backend repository");
  }

  const repoName = `nexus-v2-${randomHex(5)}`;
  const createdRepo = await githubJson("https://api.github.com/user/repos", githubToken, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: repoName,
      description: "Trendify Nexus V2 backend copy created by installer",
      private: true,
      auto_init: true,
    }),
  });

  const repository = createdRepo.html_url;
  let copiedCount = 0;

  for (const file of files) {
    const fileUrl =
      `https://api.github.com/repos/${encodeURIComponent(sourceOwner)}/${encodeURIComponent(sourceName)}/contents/` +
      file.path.split("/").map(encodeURIComponent).join("/") +
      `?ref=${encodeURIComponent(branch)}`;

    const contentResponse = await github(fileUrl, githubToken);
    if (!contentResponse.ok) {
      throw new Error(`Cannot read source file ${file.path}: ${await contentResponse.text()}`);
    }

    const fileData = await contentResponse.json();
    let content;

    if (fileData.content) {
      content = Buffer.from(
        fileData.content.replace(/\s/g, ""),
        "base64"
      ).toString("utf8");
    } else if (fileData.download_url) {
      const download = await fetch(fileData.download_url, {
        headers: { Authorization: `Bearer ${githubToken}` },
        signal: AbortSignal.timeout(30000),
      });
      if (!download.ok) throw new Error(`Cannot download ${file.path}`);
      content = await download.text();
    } else {
      throw new Error(`No readable content for ${file.path}`);
    }

    await putRepoFile(owner, repoName, file.path, content, githubToken);
    copiedCount++;
  }

  const workerName = `nexus-gw-${randomHex(5)}`;
  const gatewayUrl = `https://${workerName}.${subdomain}.workers.dev`;

  await deployGateway({
    accountId,
    token: cloudflareToken,
    workerName,
    gatewayId,
    region,
    backendUrl,
    gatewaySecret,
    relayHost,
    relayPort,
    relaySecret,
  });

  // A successful deployment is not enough: confirm that the Worker answers health checks.
  let healthy = false;
  let lastHealthError = "Gateway health check failed";

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const healthResponse = await fetch(`${gatewayUrl}/health`, {
        signal: AbortSignal.timeout(10000),
        headers: { "Cache-Control": "no-cache" },
      });
      const healthData = await healthResponse.json();

      if (healthResponse.ok && healthData.success === true) {
        healthy = true;
        break;
      }

      lastHealthError = `Health endpoint returned HTTP ${healthResponse.status}`;
    } catch (error) {
      lastHealthError = error.message || String(error);
    }

    if (attempt < 4) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  if (!healthy) {
    throw new Error(
      `Worker was deployed but health verification failed: ${lastHealthError}`
    );
  }

  return {
    success: true,
    message: "Backend repository copied and Cloudflare Gateway deployed.",
    backendRepository: repository,
    sourceBackendRepository: sourceRepo,
    copiedFiles: copiedCount,
    gatewayName: workerName,
    gatewayUrl,
    gatewayId: Number(gatewayId),
    relay: {
      host: relayHost,
      port: relayPort,
      configured: true,
    },
    nextSteps: [
      "Deploy the copied private backend repository to your hosting service only if you intend to use this copy; the Installer does not deploy it automatically.",
      "Keep the Gateway ID linked to the intended gateway row in the PostgreSQL database.",
      "The VLESS WebSocket endpoint is " + gatewayUrl + "/ws",
      "Ensure Railway RELAY_SECRET exactly matches the Relay secret entered here.",
      "Keep NEXUS_GATEWAY_SECRET equal to the backend's NEXUS_GATEWAY_SECRET.",
      "The Installer does not create a Railway TCP Proxy; configure it manually and use its public hostname and port.",
      "The Worker health endpoint confirms deployment, not end-to-end connectivity to a destination."
    ],
  };
}

/* =========================================================
   HTTP SERVER
========================================================= */

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }

  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && url.pathname === "/health") {
    return send(res, 200, { success: true, service: "installer-api" });
  }

  if (req.method !== "POST" || url.pathname !== "/api/install") {
    return send(res, 405, {
      success: false,
      message: "Method Not Allowed. Use POST /api/install",
    });
  }

  try {
    const body = await readBody(req);
    const result = await install(body);
    return send(res, 200, result);
  } catch (error) {
    console.error("[INSTALL ERROR]", error);

    return send(res, 500, {
      success: false,
      message: error?.message || "Installer failed",
    });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Trendify Nexus Installer API listening on ${PORT}`);
});
