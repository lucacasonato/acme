import { createPublicKey, type KeyObject } from "node:crypto";
import { base64url, calculateJwkThumbprint, FlattenedSign } from "npm:jose@5";

interface Directory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  revokeCert: string;
  keyChange: string;
  newAuthz?: string;
  renewalInfo?: string;
}

/**
 * Options for creating a new ACME client.
 */
export interface ClientOptions {
  /** The URL of the ACME directory.
   *
   * Some common providers:
   * - Let's Encrypt (prod): `https://acme-v02.api.letsencrypt.org/directory`
   * - Let's Encrypt (staging): `https://acme-staging-v02.api.letsencrypt.org/directory`
   */
  directoryUrl: string;

  /** The account key used to sign requests.
   *
   * This must be an RSA 512 bit or larger, or ECDSA P-256 private key. You can
   * generate one with:
   *
   * ```ts
   * import { generateKeyPair } from "node:crypto";
   * const { privateKey } = await generateKeyPair("ec", {
   *   namedCurve: "P-256",
   * });
   * ```
   */
  accountKey: KeyObject;

  /** The URL of an existing account.
   *
   * If you have an existing account, you can provide the URL here to use it.
   * Otherwise, if no account is explicitly created, the existing account URL
   * will be fetched from the directory using the account key as needed.
   */
  accountUrl?: string;
}

/**
 * Options for creating a new account with {@link Client.createAccount}.
 */
export interface CreateAccountRequest {
  /**
   * The contact information for the account.
   *
   * This should be an array of strings, each containing a contact URL. For
   * example, `["mailto:hello@example.com"]`.
   */
  contact?: string[];
  /** Whether you agree to the terms of service of the ACME provider. */
  termsOfServiceAgreed?: boolean;
  /**
   * Whether to only return an existing account (identified by the account key),
   * or create a new one if it doesn't exist.
   */
  onlyReturnExisting?: boolean;
}

/**
 * Options for updating an account with {@link Client.updateAccount}.
 */
export interface UpdateAccountRequest {
  /**
   * The new status of the account. Can only be set to "deactivated" to
   * deactivate the account.
   */
  status?: "deactivated";
  /**
   * The new contact information for the account.
   *
   * This should be an array of strings, each containing a contact URL. For
   * example, `["mailto:hello@example.com"]`.
   */
  contact?: string[];
}

/** An object representing an ACME account. */
export interface Account {
  /** The URL of the account. */
  url: string;
  /** The status of the account. */
  status: "valid" | "deactivated" | "revoked";
  /**
   * The contact information for the account, as an array of URLs (such as
   * `mailto:...`).
   */
  contact?: string[];
  /** Whether the account has agreed to the terms of service. */
  termsOfServiceAgreed?: boolean;
  /**
   * A URL to retrieve the list of orders associated to the account. This may
   * be unset if the provider does not support this feature.
   */
  orders?: string;
}

/** Options for creating a new order with {@link Client.createOrder}. */
export interface NewOrderRequest {
  /** The identifiers that should be listed in the ordered certificate. */
  identifiers: Identifier[];
  /**
   * The earliest date that the certificate should be valid. Not all providers
   * support this.
   */
  notBefore?: Date;
  /**
   * The latest date that the certificate should be valid. Not all providers
   * support this.
   */
  notAfter?: Date;
}

/** An object representing an ACME identifier. */
export interface Identifier {
  /** The type of identifier. */
  type: "dns";
  /** The value of the identifier, such as `example.com`. */
  value: string;
}

/** An object representing an ACME order. */
export interface Order {
  /** The URL of the order. */
  url: string;
  /** The status of the order. */
  status: "pending" | "ready" | "processing" | "valid" | "invalid";
  /**
   * The date the order expires. If unset, the order does not expire.
   *
   * This is encoded as a RFC 3339 date-time string.
   */
  expires?: string;
  /** The identifiers that will be listed in the certificate when issued. */
  identifiers: Identifier[];
  /**
   * The earliest date that the certificate should be valid.
   *
   * This is encoded as a RFC 3339 date-time string.
   */
  notBefore?: string;
  /**
   * The latest date that the certificate should be valid.
   *
   * This is encoded as a RFC 3339 date-time string.
   */
  notAfter?: string;
  /** An error object if the order is in "invalid" status. */
  error?: ProblemDocument;
  /** The authorizations that must be completed to issue the certificate. */
  authorizations: string[];
  /** The URL to submit the CSR to when the order is ready. */
  finalize: string;
  /**
   * The URL to download the certificate from. Only set when the order is
   * "valid".
   */
  certificate?: string;
}

/** An object representing an ACME problem document. */
export interface ProblemDocument {
  /** The type of problem. */
  type?: string;
  /** A human-readable description of the problem. */
  detail?: string;
}

/** An object representing an ACME authorization. */
export interface Authorization {
  /** The URL of the authorization. */
  url: string;
  /** The identifier that the authorization is for. */
  identifier: Identifier;
  /** The status of the authorization. */
  status:
    | "pending"
    | "valid"
    | "invalid"
    | "deactivated"
    | "expired"
    | "revoked";
  /**
   * The date the authorization expires. If unset, the authorization does not
   * expire.
   *
   * This is encoded as a RFC 3339 date-time string.
   */
  expires?: string;
  /**
   * The challenges that can be completed to validate the identifier. Any of
   * these can be completed, and only one is required.
   */
  challenges: Challenge[];
  /** Whether the identifier is a for a wildcard domain. */
  wildcard?: boolean;
}

/** An object representing an ACME challenge. */
export interface Challenge {
  /** The URL of the challenge. */
  url: string;
  /** The type of challenge. Usually "http-01" or "dns-01". */
  type: string;
  /** The status of the challenge. */
  status: "pending" | "processing" | "valid" | "invalid";
  /**
   * The date the challenge was validated, if it has been. This is guaranteed to
   * be set if the status is "valid".
   *
   * This is encoded as a RFC 3339 date-time string.
   */
  validated?: string;
  /** An error object if the challenge is in "invalid" status. */
  error?: ProblemDocument;
  /** The token that must be served to validate the challenge. */
  token?: string;
}

export interface RenewalInfo {
  /**
   * The suggested window for renewing the certificate. A client should choose
   * a random time within this window to renew the certificate.
   */
  suggestedWindow: {
    /**
     * The start of the window.
     *
     * This is encoded as a RFC 3339 date-time string.
     */
    start: string;
    /**
     * The end of the window.
     *
     * This is encoded as a RFC 3339 date-time string.
     */
    end: string;
  };
  /**
   * A URL to the ACME provider's documentation on why this certificate should
   * be renewed within the suggested window.
   */
  explanationURL?: string;

  /**
   * The number of seconds to wait before re-checking the renewal information.
   */
  retryAfter?: number;
}

/** The ACME client. */
export class Client {
  #directoryUrl: string;
  #directory: Promise<Directory> | null;
  #accountKey: KeyObject;
  #accountUrl: string | null = null;

  #nonce: string | null = null;

  #thumbprint: Promise<string> | null = null;

  /**
   * Create a new ACME client.
   *
   * @example Create a new ACME client
   * ```ts
   * import { createPublicKey, generateKeyPair } from "node:crypto";
   * import { Client } from "jsr:@luca/acme";
   *
   * const { privateKey: accountKey } = await generateKeyPair("ec", { namedCurve: "P-256" });
   *
   * const client = new Client({
   *   directoryUrl: "https://acme-v02.api.letsencrypt.org/directory",
   *   accountKey,
   * });
   * ```
   * @param options The options for the client.
   */
  constructor(options: ClientOptions) {
    this.#directoryUrl = options.directoryUrl;
    this.#directory = null;
    this.#accountKey = options.accountKey;
    this.#accountUrl = options.accountUrl || null;
  }

  #getDirectory(): Promise<Directory> {
    if (this.#directory === null) this.#directory = this.#fetchDirectory();
    return this.#directory;
  }

  async #fetchDirectory(): Promise<Directory> {
    // TODO: retry loop
    const resp = await fetch(this.#directoryUrl);
    if (!resp.ok) {
      this.#directory = null;
      throw new HttpError(resp.status, await resp.text());
    }
    return await resp.json();
  }

  /**
   * Create an account with the ACME provider using the account key. If an
   * account already exists with the key, it will be returned.
   *
   * @param options The options for creating the account.
   */
  async createAccount(options: CreateAccountRequest): Promise<Account> {
    const directory = await this.#getDirectory();
    const url = directory.newAccount;
    const req = {
      contact: options.contact,
      termsOfServiceAgreed: options.termsOfServiceAgreed,
      onlyReturnExisting: options.onlyReturnExisting,
    };
    return await this.#signedRequest<Account>(url, req, "jwk");
  }

  /**
   * Update account information such as contact details, or deactivate the
   * account.
   *
   * @param options The options for updating the account.
   * @returns The updated account object.
   */
  async updateAccount(options: UpdateAccountRequest): Promise<Account> {
    const req = {
      status: options.status,
      contact: options.contact,
    };
    if (!this.#accountUrl) {
      const account = await this.createAccount({ onlyReturnExisting: true });
      this.#accountUrl = account.url;
    }
    return await this.#signedRequest<Account>(this.#accountUrl, req, "kid");
  }

  /**
   * Create a new order for a certificate.
   *
   * This order object will initially be in the "pending" or "ready" state. You
   * may need to complete authorizations before the order is ready to be
   * finalized.
   *
   * @param newOrder The options for creating the order.
   * @returns The order object.
   */
  async createOrder(newOrder: NewOrderRequest): Promise<Order> {
    const directory = await this.#getDirectory();
    const url = directory.newOrder;
    const req = {
      identifiers: newOrder.identifiers,
      notBefore: newOrder.notBefore?.toISOString(),
      notAfter: newOrder.notAfter?.toISOString(),
    };
    return await this.#signedRequest<Order>(url, req, "kid");
  }

  /**
   * Get the current state of an order using its URL ({@link Order.url}).
   *
   * @param url The URL of the order.
   * @returns The current order object.
   */
  async getOrder(url: string): Promise<Order> {
    const order = await this.#signedRequest<Order>(url, undefined, "kid");
    order.url = url;
    return order;
  }

  /**
   * Finalize an order by submitting a CSR. This can only be done when the order
   * is in the "ready" state.
   *
   * The CSR must be a DER-encoded PKCS#10 CSR. You can generate one with:
   *
   * @param url The finalization URL from the order object ({@link Order.finalize}).
   * @param csr The DER-encoded PKCS#10 CSR.
   * @returns The current order object.
   */
  async finalizeOrder(
    order: { url: Order["url"]; finalize: Order["finalize"] },
    csr: Uint8Array,
  ): Promise<Order> {
    const req = { csr: base64url.encode(csr) };
    const res = await this.#signedRequest<Order>(order.finalize, req, "kid");
    res.url = order.url;
    return res;
  }

  /**
   * Get the current state of an authorization using its URL ({@link Authorization.url}).
   *
   * @param url The URL of the authorization.
   * @returns The current authorization object.
   */
  async getAuthorization(url: string): Promise<Authorization> {
    const auth = await this.#signedRequest<Authorization>(
      url,
      undefined,
      "kid",
    );
    auth.url = url;
    return auth;
  }

  /**
   * Get the challenge key authorization for a challenge token using the account
   * key.
   *
   * This is the value that must be served at `http://example.com/.well-known/acme-challenge/{token}`
   * or `_acme-challenge.example.com` to validate the challenge.
   *
   * @param token The challenge token from the challenge object ({@link Challenge.token}).
   * @returns The challenge key authorization.
   */
  async getChallengeKeyAuthorization(token: string): Promise<string> {
    return token + "." + await this.#getThumbprint();
  }

  /**
   * Notify the ACME provider that a challenge is set up and is ready to be
   * validated. This should be called after the challenge is set up.
   *
   * @param url The URL of the challenge ({@link Challenge.url}) from the authorization object ({@link Authorization.challenges}).
   */
  async completeChallenge(url: string): Promise<Challenge> {
    return await this.#signedRequest(url, {}, "kid");
  }

  /**
   * Get the certificate for an order from the certificate URL ({@link Order.certificate}).
   *
   * @param url The URL of the certificate.
   */
  async getCertificate(url: string): Promise<string> {
    return await this.#signedRequest(url, undefined, "kid");
  }

  async waitUntil<T extends { url: string; status: string }>(
    resource: T,
    statuses: T["status"][],
  ): Promise<T> {
    while (!statuses.includes(resource.status)) {
      await new Promise((resolve) => setTimeout(resolve, 2500));
      const url = resource.url;
      resource = await this.#signedRequest<T>(url, undefined, "kid");
      resource.url = url;
    }
    return resource;
  }

  /** Get the renewal information for a certificate. */
  async getRenewalInfo(
    certificateUniqueIdentity: string,
  ): Promise<RenewalInfo> {
    const directory = await this.#getDirectory();
    if (directory.renewalInfo === undefined) {
      throw new Error("Provider does not support renewal information");
    }
    const url = directory.renewalInfo + "/" + certificateUniqueIdentity;
    const resp = await fetch(url);
    if (resp.ok) {
      const contentType = resp.headers.get("Content-Type");
      if (contentType?.startsWith("application/json")) {
        const data: RenewalInfo = await resp.json();
        const retryAfter = resp.headers.get("Retry-After");
        if (retryAfter) data.retryAfter = parseInt(retryAfter);
        return data;
      } else {
        throw new Error("Unexpected content type: " + contentType);
      }
    } else {
      const text = await resp.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new HttpError(resp.status, text);
      }
      if (data.type && data.detail) {
        throw new AcmeError(data.type, data.detail, data.subproblems || null);
      } else {
        throw new HttpError(resp.status, text);
      }
    }
  }

  #getThumbprint() {
    if (this.#thumbprint === null) {
      this.#thumbprint = calculateJwkThumbprint(
        // deno-lint-ignore no-explicit-any
        createPublicKey(this.#accountKey).export({ format: "jwk" }) as any,
      );
    }
    return this.#thumbprint;
  }

  async #signedRequest<T>(
    url: string,
    body: unknown,
    mode: "kid" | "jwk",
  ): Promise<T> {
    let retry = 0;
    while (true) {
      try {
        return await this.#signedRequestInner(url, body, mode);
      } catch (e) {
        if (
          e instanceof AcmeError &&
          e.type === "urn:ietf:params:acme:error:badNonce" && retry < 3
        ) {
          retry++;
          continue;
        }
        throw e;
      }
    }
  }

  async #signedRequestInner<T>(
    url: string,
    body: unknown,
    mode: "kid" | "jwk",
  ): Promise<T> {
    const nonce = await this.#getNonce();
    const accountKey = this.#accountKey;
    if (!accountKey) throw new Error("No account key");
    const payload = body === undefined ? "" : JSON.stringify(body);
    let alg: string;
    let crv: string | undefined;
    if (accountKey.asymmetricKeyType === "rsa") {
      alg = "RS256";
    } else if (
      accountKey.asymmetricKeyType === "ec" &&
      accountKey.asymmetricKeyDetails?.namedCurve === "p256"
    ) {
      alg = "ES256";
    } else {
      throw new Error(
        "Unsupported key type: " + accountKey.asymmetricKeyType + " " +
          accountKey.asymmetricKeyDetails?.namedCurve,
      );
    }
    let kid: string | undefined;
    // deno-lint-ignore no-explicit-any
    let jwk: any | undefined;
    if (mode === "kid") {
      if (!this.#accountUrl) {
        const account = await this.createAccount({ onlyReturnExisting: true });
        this.#accountUrl = account.url;
      }
      kid = this.#accountUrl;
    } else if (mode === "jwk") {
      const publicKey = createPublicKey(accountKey);
      jwk = publicKey.export({ format: "jwk" });
    }
    const jws = await new FlattenedSign(new TextEncoder().encode(payload))
      .setProtectedHeader({
        alg,
        crv,
        nonce,
        url,
        kid,
        jwk,
      })
      .sign(accountKey);
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/jose+json",
      },
      body: JSON.stringify(jws),
    });
    const newNonce = resp.headers.get("Replay-Nonce");
    if (newNonce) this.#nonce = newNonce;
    if (resp.ok) {
      const contentType = resp.headers.get("Content-Type");
      if (contentType?.startsWith("application/json")) {
        const data = await resp.json();
        const location = resp.headers.get("Location");
        if (location) data.url = location;
        return data;
      } else if (contentType?.startsWith("application/pem-certificate-chain")) {
        return await resp.text() as T;
      } else {
        throw new Error("Unexpected content type: " + contentType);
      }
    } else {
      const text = await resp.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new HttpError(resp.status, text);
      }
      if (data.type && data.detail) {
        throw new AcmeError(data.type, data.detail, data.subproblems || null);
      } else {
        throw new HttpError(resp.status, text);
      }
    }
  }

  async #getNonce(): Promise<string> {
    if (this.#nonce === null) {
      const directory = await this.#getDirectory();
      const url = directory.newNonce;
      const resp = await fetch(url, { method: "HEAD" });
      const nonce = resp.headers.get("Replay-Nonce");
      if (!nonce) throw new Error("No Replay-Nonce header");
      await resp.body?.cancel();
      this.#nonce = nonce;
    }
    const nonce = this.#nonce;
    this.#nonce = null;
    return nonce;
  }
}

/**
 * An HTTP level error that was not interpretable as an {@link AcmeError}.
 *
 * The error message will contain the HTTP status code and the response body.
 */
export class HttpError extends Error {
  /** The HTTP status code of the error. */
  status: number;

  constructor(status: number, body: string) {
    super(`HTTP ${status}: ${body}`);
    this.status = status;
  }
}

/**
 * An error returned by the ACME provider in the response body. This is usually
 * a problem with the request itself, such as a validation error.
 */
export class AcmeError extends Error {
  /** The type of the error. */
  type: string;
  /** A human-readable description of the error. */
  detail: string;
  /** Additional subproblems that may have caused the error. */
  subproblems: AcmeSubproblem[] | null;

  constructor(
    type: string,
    detail: string,
    subproblems: AcmeSubproblem[] | null,
  ) {
    super(`${type}: ${detail}`);
    this.type = type;
    this.detail = detail;
    this.subproblems = subproblems;
  }
}

/**
 * An additional subproblem that may have caused an {@link AcmeError}.
 */
export interface AcmeSubproblem {
  type: string;
  detail: string;
  identifier?: Identifier;
}
