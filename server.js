const http = require("http");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// Read the unencrypted private key from the local directory safely
const KEY_PATH = path.join(__dirname, "private-key.pem");
let privateKey;

try {
  privateKey = fs.readFileSync(KEY_PATH, "utf8");
} catch (error) {
  console.error("❌ Error: 'private-key.pem' not found! Please guide your key path correctly.");
  process.exit(1);
}

/**
 * Helper function to convert buffer/string into Base64URL standard
 */
function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Main core function to construct and sign the DPoP JWT Token
 */
function generateDpopToken(method, htu) {
  // 1) Define DPoP Standard Header
  const header = {
    alg: "RS256",
    typ: "dpop+jwt"
  };

  // 2) Define DPoP Claims Payload
  const payload = {
    htm: method.toUpperCase(), // HTTP Method (GET, POST, etc.)
    htu: htu,                  // Target Resource URI (Endpoint URL)
    iat: Math.floor(Date.now() / 1000), // Issued At Timestamp
    jti: crypto.randomUUID()   // Unique Token Identifier to prevent replay attacks
  };

  // 3) Encode Header and Payload
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // 4) Sign the Input utilizing RSA-SHA256
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  sign.end();

  const signature = sign.sign({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  });

  const encodedSignature = base64url(signature);
  const token = `${signingInput}.${encodedSignature}`;

  console.log(`🔁 DPoP generated | jti: ${payload.jti} | htm: ${payload.htm}`);
  return { token, iat: payload.iat, jti: payload.jti };
}

// Instantiate the light-weight HTTP Server
const server = http.createServer((req, res) => {
  // Route handler for generating tokens dynamically via query parameters
  if (req.url.startsWith("/dpop")) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const method = url.searchParams.get("method");
    const htu = url.searchParams.get("htu");

    // Validation guard clause
    if (!method || !htu) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing required query parameters: 'method' and 'htu'" }));
      return;
    }

    const { token, iat, jti } = generateDpopToken(method, htu);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ dpop: token, iat, jti }));
  } else {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`✅ DPoP server dynamically running at http://localhost:${PORT}/dpop`);
  console.log(`💡 Usage Example: http://localhost:${PORT}/dpop?method=POST&htu=https://api.example.com/oauth/token`);
});