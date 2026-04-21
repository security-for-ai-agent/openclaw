import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { securityInterceptAuditCollector } from "./src/audit.js";
import { registerSecurityInterceptHooks } from "./src/hooks.js";

export default definePluginEntry({
  id: "security-intercept",
  name: "Security Intercept",
  description:
    "Case 1a intercept combo: detect prompt-injection / shell-injection in tool results, replace the result with a [BLOCKED] placeholder, block any follow-on tool calls in the same outer turn, and instruct the LLM to tell the user — all keyed off runId.",
  securityAuditCollectors: [securityInterceptAuditCollector],
  register(api) {
    registerSecurityInterceptHooks(api);
  },
});
