// SPDX-License-Identifier: Apache-2.0
import type { ProblemDetails } from "./generated/types.gen";

export class TavrnApiError extends Error {
  readonly problem: ProblemDetails;
  constructor(problem: ProblemDetails) {
    super(problem.detail || problem.title || `HTTP ${problem.status}`);
    this.name = "TavrnApiError";
    this.problem = problem;
  }
  get code(): string {
    return this.problem.code;
  }
  get status(): number {
    return this.problem.status;
  }
}

/** Builds a ProblemDetails object from any error response (also without a JSON body). */
export function toProblem(status: number, body: unknown, statusText = ""): ProblemDetails {
  if (body && typeof body === "object" && "code" in body && "status" in body) return body as ProblemDetails;
  return { type: "about:blank", title: statusText || `HTTP ${status}`, status, detail: "", code: status === 0 ? "network.error" : "http.error" };
}
