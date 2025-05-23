# @luca/acme

A modern and fully-featured ACME client implementation for Deno and Node.js.

## Features

- Full implementation of the
  [ACME protocol](https://tools.ietf.org/html/rfc8555) (RFC 8555)
- Support for both RSA and ECDSA account keys
- Support for `http-01` and `dns-01` challenge types
- Compatible with Let's Encrypt and other ACME providers
- Support for wildcard certificates
- Support for certificate renewal information
- Automatic retries mechanism
- Clean and type-safe API

## Basic Usage

```ts
import { generateKeyPair } from "node:crypto";
import { Client } from "jsr:@luca/acme";

// Generate or load an account key
const { privateKey: accountKey } = await generateKeyPair("ec", {
  namedCurve: "P-256",
});

// Create an ACME client
const client = new Client({
  directoryUrl: "https://acme-v02.api.letsencrypt.org/directory", // Production
  // directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory", // Staging
  accountKey,
  // Optional: provide an existing account URL if you have one
  // accountUrl: "https://acme-v02.api.letsencrypt.org/acme/acct/123456789",
});

// Create an account (or fetch existing one)
const account = await client.createAccount({
  contact: ["mailto:admin@example.com"],
  termsOfServiceAgreed: true,
});

// Create a new order for a certificate
const order = await client.createOrder({
  identifiers: [
    { type: "dns", value: "example.com" },
    { type: "dns", value: "*.example.com" }, // Optional: for wildcard
  ],
});

// Handle authorizations (complete challenges)
if (order.status === "pending") {
  for (const authzUrl of order.authorizations) {
    const authz = await client.getAuthorization(authzUrl);
    if (authz.status !== "pending") continue;

    // Find a challenge to complete (e.g., dns-01)
    const challenge = authz.challenges.find((c) => c.type === "dns-01");
    if (!challenge) continue;

    // Get the key authorization for the challenge
    const keyAuthorization = await client
      .getChallengeKeyAuthorization(challenge.token!);

    // For dns-01: Create a TXT record at _acme-challenge.example.com
    // with the SHA-256 digest of keyAuthorization (base64url encoded)
    const digest = base64url.encode(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(keyAuthorization),
        ),
      ),
    );

    // Here you would set the TXT record with your DNS provider
    // After setting the TXT record, tell the ACME server to validate it
    await client.completeChallenge(challenge.url);
  }
}

// Wait for the order to be ready
const updatedOrder = await client.waitUntil(order, ["ready", "invalid"]);

if (updatedOrder.status === "ready") {
  // Generate a key pair for the certificate
  const certKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );

  // Create a CSR
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    keys: certKeys,
    signingAlgorithm: { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
    name: `CN=example.com`,
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: "dns", value: "example.com" },
          { type: "dns", value: "*.example.com" },
        ],
        true,
      ),
    ],
  });

  // Finalize the order with the CSR
  const finalizedOrder = await client.finalizeOrder(
    updatedOrder,
    new Uint8Array(csr.rawData),
  );

  // Wait for the certificate to be issued
  const validOrder = await client.waitUntil(finalizedOrder, [
    "valid",
    "invalid",
  ]);

  if (validOrder.status === "valid") {
    // Download the certificate
    const certificate = await client.getCertificate(validOrder.certificate!);

    // Use or save the certificate
    // await Deno.writeTextFile("cert.pem", certificate);
  } else {
    console.error(
      `Order failed: ${validOrder.error?.type}: ${validOrder.error?.detail}`,
    );
  }
}
```
