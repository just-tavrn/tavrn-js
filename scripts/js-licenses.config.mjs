// SPDX-License-Identifier: Apache-2.0
// The configuration of scripts/check-js-licenses.mjs: every package (@tavrn/sdk, @tavrn/e2ee, @tavrn/bot). (A)GPL/LGPL
// stays out: an application embedding these packages must be free to choose its license. Development dependencies
// (TypeScript, Vitest, the OpenAPI generator) are not shipped and not checked.
export default {
  packages: ["sdk", "e2ee", "bot"],
  // Licenses beyond the common allow-list of check-js-licenses.mjs.
  allowed: [],
  // Packages whose metadata carries no SPDX license, verified against their license file.
  verified: {},
  exceptions: {},
};
