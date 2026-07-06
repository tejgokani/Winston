import { scanSecrets, type SecretScanReport } from "../detect/secrets.js";

export interface ScanSecretsInput {
  repoPath: string;
}

export function scanSecretsTool({ repoPath }: ScanSecretsInput): SecretScanReport {
  return scanSecrets(repoPath);
}
