import PUBLIC_SUFFIX_RULES from "./publicSuffixList.js";

let exactRules;
let wildcardRules;
let exceptionRules;

function getRuleSets() {
  if (!exactRules) {
    exactRules = new Set();
    wildcardRules = new Set();
    exceptionRules = new Set();
    for (const rule of PUBLIC_SUFFIX_RULES.split("\n")) {
      if (!rule) {
        continue;
      }
      if (rule[0] === "!") {
        exceptionRules.add(rule.slice(1));
      } else if (rule.startsWith("*.")) {
        wildcardRules.add(rule.slice(2));
      } else {
        exactRules.add(rule);
      }
    }
  }
  return { exactRules, wildcardRules, exceptionRules };
}

export function isPublicSuffix(domain) {
  if (typeof domain !== "string" || !domain) {
    return false;
  }
  const normalized = domain.toLowerCase().replace(/\.$/, "");
  const labels = normalized.split(".");
  if (labels.length < 2) {
    return true;
  }

  const { exactRules, wildcardRules, exceptionRules } = getRuleSets();
  if (exceptionRules.has(normalized)) {
    return false;
  }

  let matchedLabels = 0;
  for (let index = 0; index < labels.length; index += 1) {
    const suffix = labels.slice(index).join(".");
    if (exactRules.has(suffix)) {
      matchedLabels = Math.max(matchedLabels, labels.length - index);
    }
  }
  for (let index = 1; index < labels.length; index += 1) {
    const suffix = labels.slice(index).join(".");
    if (wildcardRules.has(suffix)) {
      matchedLabels = Math.max(matchedLabels, labels.length - index + 1);
    }
  }
  return matchedLabels === labels.length;
}
