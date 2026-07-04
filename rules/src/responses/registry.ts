import { Policy, DEFAULT_POLICY } from '../config';
import { Response } from '../types';
import { makeAlertResponse } from './alert';
import { disableExtensionResponse } from './disableExtension';
import { closeTabResponse } from './closeTab';
import { removeCookieResponse } from './removeCookie';
import { cancelDownloadResponse } from './cancelDownload';

/**
 * The fixed registry of responses an authored rule may reference **by id** (ADR-002). A user rule names a
 * response; it can never supply one. Unknown ids are rejected by the validator.
 */
export function buildResponseRegistry(_policy: Policy = DEFAULT_POLICY): Map<string, Response<unknown>> {
  const registry = new Map<string, Response<unknown>>();
  registry.set('alert', makeAlertResponse<unknown>());
  registry.set('disableExtension', disableExtensionResponse as unknown as Response<unknown>);
  registry.set('closeTab', closeTabResponse as unknown as Response<unknown>);
  registry.set('removeCookie', removeCookieResponse as unknown as Response<unknown>);
  registry.set('cancelDownload', cancelDownloadResponse as unknown as Response<unknown>);
  return registry;
}

/** The set of valid response ids — derived from the registry so it can't drift. */
export const RESPONSE_IDS: ReadonlySet<string> = new Set(buildResponseRegistry().keys());
