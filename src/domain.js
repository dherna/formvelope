import { isPublicSuffix } from "./publicSuffix.js";

export function normalizeAllowedDomain(entry) {
  if (typeof entry === "string") {
    return { domain: entry, includeSubdomains: true };
  }
  if (!entry || typeof entry !== "object") {
    return undefined;
  }
  return {
    domain: entry.domain,
    includeSubdomains: entry.includeSubdomains === true
  };
}

export function isValidDomain(domain) {
  if (typeof domain !== "string" || !domain || domain !== domain.toLowerCase()) {
    return false;
  }
  try {
    const url = new URL(`https://${domain}`);
    return url.hostname === domain &&
      url.pathname === "/" &&
      !url.port &&
      !url.username &&
      !url.password &&
      !isPublicSuffix(domain);
  } catch {
    return false;
  }
}

export function isValidAllowedDomain(entry) {
  if (
    !entry ||
    typeof entry !== "object" ||
    typeof entry.domain !== "string" ||
    typeof entry.includeSubdomains !== "boolean"
  ) {
    return false;
  }
  return isValidDomain(entry.domain);
}

export function hostPermissionPatterns(entry) {
  const allowedDomain = normalizeAllowedDomain(entry);
  if (!allowedDomain) {
    return [];
  }
  const { domain, includeSubdomains } = allowedDomain;
  const patterns = [`https://${domain}/*`];
  if (includeSubdomains) {
    patterns.push(`https://*.${domain}/*`);
  }
  return patterns;
}

export function domainMatchesAllowedDomain(hostname, entry) {
  const allowedDomain = normalizeAllowedDomain(entry);
  if (!allowedDomain) {
    return false;
  }
  const { domain, includeSubdomains } = allowedDomain;
  return hostname === domain ||
    (includeSubdomains && hostname.endsWith(`.${domain}`));
}
