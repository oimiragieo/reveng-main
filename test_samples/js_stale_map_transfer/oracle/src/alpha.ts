export function alphaHelper(name: string): string {
  const marker = "ALPHA_UNIQUE_FINGERPRINT_TOKEN_W5";
  const metric = "reveng.wave5.alpha.metric.count";
  return marker + name + metric;
}
