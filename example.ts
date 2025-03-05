import {
  createPrivateKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { Client } from "./mod.ts";
import { base64url } from "jose";
import * as x509 from "@peculiar/x509";

let accountKey: KeyObject;
try {
  const key = await Deno.readTextFile("account.pem");
  accountKey = createPrivateKey(key);
} catch (e) {
  if (e instanceof Deno.errors.NotFound) {
    ({ privateKey: accountKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    }));
    await Deno.writeTextFile(
      "account.pem",
      accountKey.export({ format: "pem", type: "pkcs8" }) as string,
    );
  } else {
    throw e;
  }
}

const domain = "example4.com";

const client = new Client({
  directoryUrl: "https://localhost:14000/dir",
  accountKey,
});

await client.createAccount({
  contact: ["mailto:hello+letsencrypt@lcas.dev"],
  termsOfServiceAgreed: true,
});

let order = await client.createOrder({
  identifiers: [
    { type: "dns", value: domain },
    { type: "dns", value: `*.${domain}` },
  ],
});

if (order.status === "pending") {
  for (const authzUrl of order.authorizations) {
    const authz = await client.getAuthorization(authzUrl);
    if (authz.status !== "pending") continue;

    let challenge = authz.challenges.find((c) => c.type === "dns-01")!;

    const keyAuthorization = await client.getChallengeKeyAuthorization(
      challenge.token!,
    );

    // // update pebble-challtestsrv to use the keyAuthorization
    // const resp = await fetch("http://localhost:8055/clear-txt", {
    //   method: "POST",
    //   headers: {
    //     "Content-Type": "application/json",
    //   },
    //   body: JSON.stringify({
    //     host: `_acme-challenge.${domain}.`,
    //   }),
    // });
    // if (!resp.ok) {
    //   throw new Error(`Failed to set TXT record: ${resp.statusText}`);
    // }
    const digest = base64url.encode(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(keyAuthorization),
        ),
      ),
    );
    const resp2 = await fetch("http://localhost:8055/set-txt", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        host: `_acme-challenge.${domain}.`,
        value: digest,
      }),
    });
    if (!resp2.ok) {
      throw new Error(`Failed to set TXT record: ${resp2.statusText}`);
    }

    challenge = await client.completeChallenge(challenge.url);
    console.log(challenge);
  }
}

order = await client.waitUntil(order, ["ready", "invalid"]);

if (order.status === "ready") {
  // create a rsa private key
  const alg = {
    name: "ECDSA",
    namedCurve: "P-384",
    hash: "SHA-384",
  };
  const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    keys,
    signingAlgorithm: alg,
    name: `CN=${domain}`,
    extensions: [
      new x509.SubjectAlternativeNameExtension([
        { type: "dns", value: domain },
        { type: "dns", value: `*.${domain}` },
      ], true),
    ],
  });

  order = await client.finalizeOrder(order, new Uint8Array(csr.rawData));
  console.log(order);

  order = await client.waitUntil(order, ["valid", "invalid"]);
  console.log("Certificate issued");

  const cert = await client.getCertificate(order.certificate!);
  await Deno.writeTextFile("cert.pem", cert);
}
