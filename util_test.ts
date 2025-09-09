import { parseRetryAfter } from "./util.ts";
import { assertEquals } from "jsr:@std/assert";

Deno.test("parseRetryAfter", async (t) => {
  // RFC 7231: Delay in seconds format
  await t.step("Retry-After: 0 (zero delay)", () => {
    const headers = new Headers({ "Retry-After": "0" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(now.getTime());
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  await t.step("Retry-After: 120 (2 minutes)", () => {
    const headers = new Headers({ "Retry-After": "120" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(now.getTime() + 120 * 1000);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  await t.step("Retry-After: 86400 (24 hours)", () => {
    const headers = new Headers({ "Retry-After": "86400" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(now.getTime() + 86400 * 1000);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  // RFC 7231: HTTP-date format
  await t.step("Retry-After: HTTP-date format", () => {
    const httpDate = "Fri, 31 Dec 2024 23:59:59 GMT";
    const headers = new Headers({ "Retry-After": httpDate });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(httpDate);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  await t.step("Retry-After: Alternative HTTP-date format", () => {
    const httpDate = "Friday, 31-Dec-24 23:59:59 GMT";
    const headers = new Headers({ "Retry-After": httpDate });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(httpDate);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  await t.step("Retry-After: RFC 850 date format", () => {
    const httpDate = "Fri Dec 31 23:59:59 2024";
    const headers = new Headers({ "Retry-After": httpDate });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(httpDate);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  // Edge cases and invalid inputs
  await t.step("Retry-After: negative delay should be invalid", () => {
    const headers = new Headers({ "Retry-After": "-10" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    assertEquals(retryAfter, null);
  });

  await t.step("Retry-After: non-numeric string", () => {
    const headers = new Headers({ "Retry-After": "abc" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    assertEquals(retryAfter, null);
  });

  await t.step("Retry-After: invalid date format", () => {
    const headers = new Headers({ "Retry-After": "Invalid Date String" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    assertEquals(retryAfter, null);
  });

  await t.step(
    "Retry-After: decimal number should be treated as invalid",
    () => {
      const headers = new Headers({ "Retry-After": "120.5" });
      const now = new Date();
      const retryAfter = parseRetryAfter(headers, now);
      assertEquals(retryAfter, null);
    },
  );

  await t.step("Retry-After: number with leading/trailing whitespace", () => {
    const headers = new Headers({ "Retry-After": "  120  " });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(now.getTime() + 120 * 1000);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  await t.step("Retry-After: HTTP-date with whitespace", () => {
    const httpDate = "  Fri, 31 Dec 2024 23:59:59 GMT  ";
    const headers = new Headers({ "Retry-After": httpDate });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(httpDate.trim());
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  // Missing or empty header
  await t.step("Missing Retry-After header", () => {
    const headers = new Headers();
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    assertEquals(retryAfter, null);
  });

  await t.step("Empty Retry-After header", () => {
    const headers = new Headers({ "Retry-After": "" });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    assertEquals(retryAfter, null);
  });

  await t.step("Retry-After header with only whitespace", () => {
    const headers = new Headers({ "Retry-After": "   " });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    assertEquals(retryAfter, null);
  });

  // Large values
  await t.step("Retry-After: very large delay", () => {
    const headers = new Headers({ "Retry-After": "2147483647" }); // Max 32-bit signed int
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(now.getTime() + 2147483647 * 1000);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });

  // Past date handling
  await t.step("Retry-After: past HTTP-date", () => {
    const pastDate = "Fri, 31 Dec 2020 23:59:59 GMT";
    const headers = new Headers({ "Retry-After": pastDate });
    const now = new Date();
    const retryAfter = parseRetryAfter(headers, now);
    const expected = new Date(pastDate);
    assertEquals(retryAfter?.getTime(), expected.getTime());
  });
});
