import {
  type Span,
  type SpanKind,
  type SpanOptions,
  SpanStatusCode,
  trace,
} from "@opentelemetry/api";
import { AcmeError } from "@luca/acme";

const tracer = trace.getTracer("@luca/acme");

function reportError(span: Span, err: unknown) {
  if (err instanceof AcmeError) span.setAttribute("acme.error.type", err.type);
  span.recordException(err as Error);
  span.setStatus({ code: SpanStatusCode.ERROR });
}

export function startActiveSpan<
  This extends unknown,
  Args extends unknown[],
  Return,
>(
  name: string,
  options: SpanOptions,
  thisArg: This,
  args: Args,
  fn: (...args: Args) => Return,
): Return {
  return tracer.startActiveSpan(name, options, (span: Span) => {
    try {
      const res = fn.apply(thisArg, args);
      if (typeof res === "object" && res && "then" in res) {
        return (res as unknown as Promise<Return>)
          .then((result) => {
            span.setStatus({ code: SpanStatusCode.OK });
            return result;
          })
          .catch((err) => {
            reportError(span, err);
            throw err;
          })
          .finally(() => span.end()) as Return;
      } else {
        span.setStatus({ code: SpanStatusCode.OK });
        span.end();
        return res;
      }
    } catch (err) {
      reportError(span, err);
      span.end();
      throw err;
    }
  });
}

export function instrument(name?: string, opts: { kind?: SpanKind } = {}) {
  return function <This, Args extends unknown[], Return>(
    originalMethod: (this: This, ...args: Args) => Return,
    context: ClassMethodDecoratorContext<
      This,
      (this: This, ...args: Args) => Return
    >,
  ): (this: This, ...args: Args) => Return {
    const finalName = name || context.name.toString();
    return function (this: This, ...args: Args): Return {
      return startActiveSpan(finalName, opts, this, args, originalMethod);
    };
  };
}
