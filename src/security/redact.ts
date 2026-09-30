const textPatterns: Array<[RegExp, string | ((substring: string, ...args: string[]) => string)]> = [
  [
    /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----/gi,
    '[REDACTED PRIVATE KEY]'
  ],
  [/\b(authorization\s*:\s*(?:bearer|basic))\s+[^\r\n]+/gi, '$1 [REDACTED]'],
  [/\b(cookie|set-cookie)\s*:\s*[^\r\n]+/gi, '$1: [REDACTED]'],
  [
    /\b([A-Z0-9_.-]*(?:token|password|passwd|secret|api[_-]?key|access[_-]?key(?:_id)?|private[_-]?key|session(?:id)?|cookie)[A-Z0-9_.-]*)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s;,]+)/gi,
    '$1=[REDACTED]'
  ],
  [/\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+)\b/g, '[REDACTED]'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED]']
];

export function redactText(text: string): string {
  let value = text;
  for (const [pattern, replacement] of textPatterns) {
    value =
      typeof replacement === 'string'
        ? value.replace(pattern, replacement)
        : value.replace(pattern, replacement);
  }
  return value;
}

export function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, redactValue(item)])
    );
  }
  return value;
}
