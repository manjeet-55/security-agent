import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Consent records go to a throwaway directory, never the developer's real ~/.config/secagent.
process.env.SECAGENT_CONFIG_DIR = mkdtempSync(path.join(os.tmpdir(), 'secagent-config-'));
