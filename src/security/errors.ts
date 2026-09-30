export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly detail?: unknown;

  constructor(statusCode: number, code: string, message: string, detail?: unknown) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.detail = detail;
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
