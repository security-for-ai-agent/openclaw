// Public surface for the core content scanner.
//
// Core call sites import from here; the scanner is a singleton backed by
// OpenClawConfig, NOT a plugin — it runs as part of the trusted core and
// cannot be unloaded by an operator mis-configuration.

export {
  ContentScanner,
  getContentScanner,
  initializeContentScanner,
  reconfigureContentScanner,
  __resetContentScannerForTests,
} from "./scanner.js";

export type {
  ContentScannerConfig,
  ContentScannerMode,
  ScannerBeforePromptBuildInput,
  ScannerBeforePromptBuildResult,
  ScannerBeforeToolCallInput,
  ScannerBeforeToolCallResult,
  ScannerAfterToolCallInput,
  ScannerMessageSendingInput,
  ScannerMessageSendingResult,
  ScannerSessionEndInput,
  ScannerToolResultPersistInput,
  ScannerToolResultPersistResult,
} from "./scanner.js";

export type { ThreatClass, ContentCase, Detection } from "./detectors.js";

export type { EgressClass, EgressMatch, EgressScanResult } from "./egress-scan.js";
