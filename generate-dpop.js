const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// 1) Read the private key file securely
const KEY_PATH = path.join(__dirname, "private-key.pem");
let privateKey;

try {
  privateKey = fs.readFileSync(KEY_PATH, "utf8");
} catch (error) {
  console.error("❌ Error: 'private-key.pem' not found!");
  process.exit(1);
}

// 2) Configuration Example (Generalized mock endpoints)
const method = "POST";
const htu = "https://api.example.com/v1/oauth/access-token";

// 3) Construct Payload (RFC 9449 Standard Compliance)
const payload = {
  jti: crypto.randomUUID(), // Unique identifier to mitigate replay attacks
  htm: method,
  htu: htu,
  iat: Math.floor(Date.now() / 1000)
};

// 4) Construct Header
const header = {
  alg: "RS256",
  typ: "dpop+jwt"
};

// 5) Base64URL Encoding helper function
function base64url(input) {
  return input
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// 6) Encode Header and Payload components
const encodedHeader = base64url(Buffer.from(JSON.stringify(header)));
const encodedPayload = base64url(Buffer.from(JSON.stringify(payload)));
const signingInput = `${encodedHeader}.${encodedPayload}`;

// 7) Generate Cryptographic RS256 Signature using Node.js Crypto API
const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), {
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PADDING
});

const encodedSignature = base64url(signature);

// 8) Formulate final DPoP Token format (Header.Payload.Signature)
const dpop = `${signingInput}.${encodedSignature}`;

console.log("\n=================== YOUR GENERATED DPoP TOKEN ===================");
console.log(dpop);
console.log("=================================================================\n");
console.log("💡 How to use: Copy the token above and paste it inside Postman Header → 'DPoP'");