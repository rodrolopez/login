import { context, propagation, SpanKind, SpanStatusCode, trace } from '@opentelemetry/api';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { NodeSDK } from '@opentelemetry/sdk-node';
import type { RequestHandler } from 'express';

let sdk: NodeSDK | undefined;

function readTraceExporterUrl(environment: NodeJS.ProcessEnv): string {
  const configured = environment.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT?.trim();
  if (!configured) {
    throw new Error('OTLP trace exporter endpoint must be configured');
  }

  let endpoint: URL;
  try {
    endpoint = new URL(configured);
  } catch {
    throw new Error('Invalid OTLP trace exporter endpoint');
  }

  if (
    !['http:', 'https:'].includes(endpoint.protocol) ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash
  ) {
    throw new Error('Invalid OTLP trace exporter endpoint');
  }

  return endpoint.toString();
}

export async function startTelemetry(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<() => Promise<void>> {
  const enabled = environment.NODE_ENV === 'production' || environment.OTEL_ENABLED === 'true';
  if (!enabled) return async () => undefined;
  if (sdk) throw new Error('OpenTelemetry has already been initialized');

  sdk = new NodeSDK({
    serviceName: environment.OTEL_SERVICE_NAME?.trim() || 'identity-api',
    traceExporter: new OTLPTraceExporter({ url: readTraceExporterUrl(environment) }),
    instrumentations: [],
  });
  sdk.start();

  return async () => {
    const activeSdk = sdk;
    sdk = undefined;
    await activeSdk?.shutdown();
  };
}

const traceHeaderGetter = {
  get(carrier: Record<string, string | undefined>, key: string): string | undefined {
    return carrier[key.toLowerCase()];
  },
  keys(carrier: Record<string, string | undefined>): string[] {
    return Object.keys(carrier);
  },
};

/**
 * Starts a low-cardinality HTTP server span and emits a safe structured access log.
 * URLs, query strings, headers, request bodies, and user identifiers are intentionally omitted.
 */
export const requestTraceMiddleware: RequestHandler = (request, response, next) => {
  const tracer = trace.getTracer('identity-api.http');
  const carrier = {
    traceparent: request.header('traceparent'),
    tracestate: request.header('tracestate'),
  };
  const parentContext = propagation.extract(context.active(), carrier, traceHeaderGetter);
  const span = tracer.startSpan('http.server.request', { kind: SpanKind.SERVER }, parentContext);
  const spanContext = span.spanContext();
  const traceId = spanContext.traceId;
  const startedAt = performance.now();
  let finished = false;

  span.setAttribute('http.request.method', request.method);
  if (spanContext.traceId !== '00000000000000000000000000000000') {
    response.setHeader('X-Trace-Id', traceId);
  }

  const finish = (): void => {
    if (finished) return;
    finished = true;
    const durationMs = Math.max(0, Math.round(performance.now() - startedAt));
    span.setAttribute('http.response.status_code', response.statusCode);
    if (response.statusCode >= 500) span.setStatus({ code: SpanStatusCode.ERROR });

    if (process.env.NODE_ENV === 'production' && traceId !== '00000000000000000000000000000000') {
      process.stdout.write(
        `${JSON.stringify({
          severity: 'INFO',
          event: 'http.request.completed',
          trace_id: traceId,
          method: request.method,
          status_code: response.statusCode,
          duration_ms: durationMs,
        })}\n`,
      );
    }

    span.end();
  };

  response.once('finish', finish);
  response.once('close', finish);
  context.with(trace.setSpan(parentContext, span), next);
};
