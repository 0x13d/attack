/**
 * The payload shape of a `Scope.COOKIE` signal. The rules and the `removeCookie` response consume this type;
 * the extension's cookie signal source (which wraps `chrome.cookies.onChanged`) produces it.
 */
export interface CookiePayload {
  cookie: chrome.cookies.Cookie;
  cause: string;
}
