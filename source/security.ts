import * as path from 'path';
import { MCPServerSettings } from './types';

export function isLoopbackHost(host: string): boolean {
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

export function resolveCorsOrigin(origin: string | undefined, settings: MCPServerSettings): string {
  const allowed = settings.allowedOrigins && settings.allowedOrigins.length > 0
    ? settings.allowedOrigins
    : ['http://127.0.0.1', 'http://localhost'];

  if (origin && allowed.includes(origin)) return origin;
  return allowed[0];
}

export function checkAccess(headers: Record<string, string | string[] | undefined>, settings: MCPServerSettings): string | null {
  if (!settings.requireAccessToken) return null;
  const expected = settings.accessToken || '';
  if (!expected) return 'Access token is required by settings but no token is configured.';
  const raw = headers['authorization'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value === `Bearer ${expected}`) return null;
  return 'Invalid or missing access token.';
}

export function normalizePath(input: string): string {
  return path.resolve(input).replace(/\\/g, '/');
}

export function sameWorkspace(left: string, right: string): boolean {
  if (!left || !right) return false;
  return normalizePath(left) === normalizePath(right);
}

export function ensureWorkspace(args: any, projectRoot: string, settings: MCPServerSettings): string | null {
  if (!settings.workspaceGuard) return null;
  const clientRoot = args?.clientWorkspaceRoot;
  if (!clientRoot) return null;
  if (!sameWorkspace(clientRoot, projectRoot)) {
    return `Workspace guard blocked this request. Codex workspace '${clientRoot}' does not match Cocos project '${projectRoot}'.`;
  }
  return null;
}

export function requireConfirm(args: any, actionKey: string, writeActions: string[] | undefined, settings: MCPServerSettings): string | null {
  if (!settings.requireConfirmForWrite) return null;
  if (!writeActions || !writeActions.includes(actionKey)) return null;
  if (args?.confirm === true) return null;
  return `Action '${actionKey}' requires confirm: true.`;
}
