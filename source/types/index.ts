export interface MCPServerSettings {
  host: string;
  port: number;
  autoStart: boolean;
  enableDebugLog: boolean;
  allowedOrigins: string[];
  accessToken?: string;
  requireAccessToken: boolean;
  workspaceGuard: boolean;
  requireConfirmForWrite: boolean;
}

export interface ServerStatus {
  running: boolean;
  host: string;
  port: number;
  projectRoot: string;
  tools: number;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: any;
}

export interface ToolResponse {
  success: boolean;
  data?: any;
  message?: string;
  error?: string;
  warning?: string;
  instruction?: string;
}

export interface ToolContext {
  getSettings(): MCPServerSettings;
  getProjectRoot(): string;
  getToolDefinitions(): ToolDefinition[];
}

export interface RegisteredTool extends ToolDefinition {
  writeActions?: string[];
  execute(args: any): Promise<ToolResponse>;
}
