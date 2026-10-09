
import net from "node:net";
import { timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 443);
const SECRET = String(process.env.RELAY_SECRET || "");
const MAX_SECRET_LENGTH = 256;
const MAX_HOST_LENGTH = 255;

if (!SECRET) {
  console.error("FATAL: RELAY_SECRET is required");
  process.exit(1);
}

const expectedSecret = Buffer.from(SECRET, "utf8");

if (
  expectedSecret.length < 16 ||
  expectedSecret.length > MAX_SECRET_LENGTH
) {
  console.error("FATAL: RELAY_SECRET must be 16-256 bytes");
  process.exit(1);
}

const server = net.createServer((client) => {
  client.setNoDelay(true);

  let remote = null;
  let buffer = Buffer.alloc(0);
  let stage = "secretLength";
  let secretLength = 0;
  let hostLength = 0;
  let finished = false;

  const headerTimer = setTimeout(() => {
    if (stage !== "connected") client.destroy();
  }, 10000);

  function reject(reason) {
    if (finished) return;
    finished = true;
    clearTimeout(headerTimer);
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

        if (
          secretLength < 16 ||
          secretLength > MAX_SECRET_LENGTH
        ) {
          return reject("Invalid secret length");
        }

        stage = "secret";
      }

      if (stage === "secret") {
        if (buffer.length < secretLength) return;

        const receivedSecret = buffer.subarray(0, secretLength);
        buffer = buffer.subarray(secretLength);

        if (
          receivedSecret.length !== expectedSecret.length ||
          !timingSafeEqual(receivedSecret, expectedSecret)
        ) {
          return reject("Authentication failed");
        }

        stage = "hostLength";
      }

      if (stage === "hostLength") {
        if (buffer.length < 2) return;

        hostLength = buffer.readUInt16BE(0);
        buffer = buffer.subarray(2);

        if (hostLength < 1 || hostLength > MAX_HOST_LENGTH) {
          return reject("Invalid host length");
        }

        stage = "target";
      }

      if (stage === "target") {
        if (buffer.length < hostLength + 2) return;

        const host = buffer
          .subarray(0, hostLength)
          .toString("utf8");

        const port = buffer.readUInt16BE(hostLength);
        const initialPayload = buffer.subarray(hostLength + 2);

        buffer = Buffer.alloc(0);
        stage = "connecting";

        if (
          !host ||
          /[\0\r\n]/.test(host) ||
          !Number.isInteger(port) ||
          port < 1 ||
          port > 65535
        ) {
          return reject("Invalid destination");
        }

        clearTimeout(headerTimer);
        client.pause();
        client.removeListener("data", onData);

        console.log("CONNECT TARGET:", host, port);

        try {
          remote = net.connect({ host, port });
          remote.setNoDelay(true);

          remote.once("connect", () => {
            if (finished) {
              remote?.destroy();
              return;
            }

            stage = "connected";
            console.log("TARGET CONNECTED:", host, port);

            if (initialPayload.length) {
              remote.write(initialPayload);
            }

            client.pipe(remote);
            remote.pipe(client);
            client.resume();
          });

          remote.on("error", (err) => {
            console.log("REMOTE ERROR:", err.message);
            client.destroy();
          });

          remote.on("close", () => {
            client.destroy();
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

  client.on("error", (err) => {
    console.log("CLIENT ERROR:", err.message);
    remote?.destroy();
  });

  client.on("close", () => {
    finished = true;
    clearTimeout(headerTimer);
    remote?.destroy();
  });
});

server.on("error", (err) => {
  console.error("SERVER ERROR:", err);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("=================================");
  console.log("Trendify Nexus Dynamic TCP Relay");
  console.log("PORT:", PORT);
  console.log("AUTH: enabled");
  console.log("=================================");
});
