import * as fs from 'fs';
import * as path from 'path';
import { MCPServerSettings } from './types';

export const DEFAULT_SETTINGS: MCPServerSettings = {
  host: '127.0.0.1',
  port: 3000,
  autoStart: false,
  enableDebugLog: false,
  allowedOrigins: ['http://127.0.0.1', 'http://localhost'],
  requireAccessToken: false,
  workspaceGuard: true,
  requireConfirmForWrite: true
};

function getSettingsFile(): string {
  return path.join(Editor.Project.path, 'settings', 'kam-ai-mcp.json');
}

function ensureSettingsDir(): void {
  const dir = path.dirname(getSettingsFile());
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export function readSettings(): MCPServerSettings {
  try {
    ensureSettingsDir();
    const file = getSettingsFile();
    if (!fs.existsSync(file)) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch (error) {
    console.error('[kam-ai-mcp] Failed to read settings:', error);
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(settings: MCPServerSettings): void {
  ensureSettingsDir();
  fs.writeFileSync(getSettingsFile(), JSON.stringify({ ...DEFAULT_SETTINGS, ...settings }, null, 2));
}
