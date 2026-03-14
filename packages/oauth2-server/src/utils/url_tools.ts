export function normalizeUrl(url: string, origin: string): string {
  if (url && /^\/(?!\/)/.test(url)) {
    // Relative path, resolve against discovery URL's origin
    return `${origin}${url}`;
  }
  return url;
}

export function getOriginFromUrl(url: string): string | undefined {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.origin !== "null" ? parsedUrl.origin : undefined;
  } catch {
    return undefined;
  }
}
