import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import { TOOLS, handleToolCall } from "./tools.js";
import { logInfo, logError } from "./pharosRpc.js";

/**
 * Boots the MCP server using StdioServerTransport.
 * Asserts strict error isolation and processes exit notifications gracefully.
 */
async function main() {
  logInfo("Initializing Pharos Autonomous Guardian (PAG) MCP Server...");

  const server = new Server(
    {
      name: "pharos-autonomous-guardian",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Set up list tools request handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    logInfo("Received request: List available tools.");
    return {
      tools: TOOLS
    };
  });

  // Set up call tool request handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    logInfo(`Received request: Call tool [${name}]`);
    
    // Pass execution to the router
    return await handleToolCall(name, args);
  });

  // Hook Stdio Server Transport
  const transport = new StdioServerTransport();
  
  // Set up exit hooks for clean termination
  process.on("SIGINT", async () => {
    logInfo("Interrupted. Shutting down MCP server...");
    await server.close();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    logInfo("Terminated. Shutting down MCP server...");
    await server.close();
    process.exit(0);
  });

  try {
    await server.connect(transport);
    logInfo("Pharos Autonomous Guardian MCP Server successfully connected to Stdio transport.");
  } catch (error) {
    logError("Fatal error bootstrapping MCP server transport", error);
    process.exit(1);
  }
}

// Execute and capture unhandled failures to protect the host process
main().catch((error) => {
  logError("Uncaught error in main loop execution", error);
  process.exit(1);
});
