/**
 * Parse the Retry-After header as per spec:
 * https://datatracker.ietf.org/doc/html/rfc9110#section-10.2.3
 */
export function parseRetryAfter(headers: Headers, now: Date): Date | null {
  const retryAfter = headers.get("Retry-After");
  if (!retryAfter) return null;
  // TODO
  return new Date();
}
