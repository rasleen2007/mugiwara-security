/**
 * Full-page navigation used after auth state changes (login/signup/logout).
 *
 * Kept as an injectable seam so component tests can observe redirects
 * without relying on jsdom's non-configurable window.location.
 */

export function navigateTo(path: string): void {
  window.location.assign(path);
}
