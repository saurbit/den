export function normalizeUrl(url: string, origin: string): string {
  if (url && /^\/(?!\/)/.test(url)) {
    // Relative path, resolve against discovery URL's origin
    return `${origin}${url}`;
  }
  return url;
}
