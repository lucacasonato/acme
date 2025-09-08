/**
 * Parse the Retry-After header as per spec:
 * https://datatracker.ietf.org/doc/html/rfc9110#section-10.2.3
 */
export function parseRetryAfter(
  headers: Headers,
  now: Date = new Date(),
): Date | null {
  const retryAfter = headers.get("Retry-After");
  if (!retryAfter) return null;

  const value = retryAfter.trim();
  if (value.length === 0) return null;

  // delta-seconds (non-negative integer)
  if (/^\d+$/.test(value)) {
    const seconds = Number(value);
    return new Date(now.getTime() + seconds * 1000);
  }

  // HTTP-date: ensure it's actually a date-like string (contains letters)
  if (!/[a-zA-Z]/.test(value)) return null;
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return null;
  return new Date(timestamp);
}
