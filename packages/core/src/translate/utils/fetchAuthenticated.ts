import { createUserTokenFetch } from '@generaltranslation/api';
import type { TranslationRequestConfig } from '../../types';
import { fetchWithTimeout } from './fetchWithTimeout';

export function fetchAuthenticated(
  config: TranslationRequestConfig,
  input: string | URL | Request,
  init: RequestInit,
  timeout?: number
): Promise<Response> {
  const fetchImplementation: typeof fetch = (url, options) =>
    fetchWithTimeout(url, options ?? {}, timeout);
  const provider = config.apiKey ? undefined : config.userTokenProvider;
  return (
    provider
      ? createUserTokenFetch(fetchImplementation, provider)
      : fetchImplementation
  )(input, init);
}
