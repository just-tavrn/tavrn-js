// SPDX-License-Identifier: MPL-2.0
import { MemorySearchBackend } from "../src/search";
import { backendContract } from "../src/search/contract";

backendContract("memory", () => new MemorySearchBackend());
