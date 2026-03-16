# GhidrAssistMCP

> **Fork Notice**: This is a fork of [symgraph/GhidrAssistMCP](https://github.com/symgraph/GhidrAssistMCP) (originally by [jtang613](https://github.com/jtang613/GhidrAssistMCP)) with additional features including Ghidra 12.0.4 support, project management CRUD, full autopilot tools, and early MCP server startup.

A powerful Ghidra extension that provides an MCP (Model Context Protocol) server, enabling AI assistants and other tools to interact with Ghidra's reverse engineering capabilities through a standardized API.

## Overview

GhidrAssistMCP bridges the gap between AI-powered analysis tools and Ghidra's comprehensive reverse engineering platform. By implementing the Model Context Protocol, this extension allows external AI assistants, automated analysis tools, and custom scripts to seamlessly interact with Ghidra's analysis capabilities.

### Key Features

- **MCP Server Integration**: Full Model Context Protocol server implementation using official SDK
- **Early Server Start**: MCP server starts as soon as the tool opens, before any program/file is loaded
- **Dual HTTP Transports**: Supports SSE and Streamable HTTP transports for maximum client compatibility
- **59 Built-in Tools**: Comprehensive set of analysis, project management, and autopilot tools
- **Full Project CRUD**: Create folders, import/export/delete/rename/move files, save projects
- **Autopilot Support**: Auto-analysis, undo/redo, navigation, export — everything needed for AI-driven reverse engineering
- **5 MCP Resources**: Static data resources for program info, functions, strings, imports, and exports
- **5 MCP Prompts**: Pre-built analysis prompts for common reverse engineering tasks
- **Result Caching**: Intelligent caching system to improve performance for repeated queries
- **Async Task Support**: Long-running operations execute asynchronously with task management
- **Multi-Program Support**: Work with multiple open programs simultaneously using `program_name` parameter
- **Multi-Window Support**: Single MCP server shared across all CodeBrowser windows with intelligent focus tracking
- **Active Context Awareness**: Automatic detection of which binary window is in focus, with context hints in all tool responses
- **Configurable UI**: Easy-to-use interface for managing tools and monitoring activity
- **Real-time Logging**: Track all MCP requests and responses with detailed logging
- **Dynamic Tool Management**: Enable/disable tools individually with persistent settings
- **Ghidra 12.0.4 Compatible**: Uses modern Ghidra APIs (ProgramLoader, etc.)

## What's New in This Fork

### Early MCP Server Start
The plugin now extends `Plugin` instead of `ProgramPlugin`, so the MCP server starts **immediately when the tool opens** — before any file or program is loaded. Project management tools (list files, create folders, import binaries) work right away.

### Project Management CRUD (10 tools)
Full create/read/update/delete operations for the Ghidra project:
- Browse project tree, create folders, import binaries from disk
- Open/close programs (closing all programs is now allowed — server stays active)
- Delete, rename, and move files between folders
- Get project info and save all changes

### Autopilot Tools (4 tools)
Everything needed for AI-driven reverse engineering:
- Run auto-analysis on demand
- Export programs to binary, C header, or Intel HEX
- Undo/redo with multi-step support
- Navigate to any address or symbol

### Ghidra 12.0.4 Support
- Migrated from deprecated `AutoImporter` to new `ProgramLoader.builder()` fluent API
- Zero removal warnings when building against Ghidra 12.0.4
- Uses modern `Loaded<Program>` / `LoadResults` APIs

## Clients

Shameless self-promotion: [GhidrAssist](https://github.com/jtang613/GhidrAssist) supports GhidrAssistMCP right out of the box.

## Screenshots

![Screenshot](https://github.com/jtang613/GhidrAssistMCP/blob/master/res/Screenshot1.png)
![Screenshot](https://github.com/jtang613/GhidrAssistMCP/blob/master/res/Screenshot2.png)

## Installation

### Prerequisites

- **Ghidra 11.4+** (tested with Ghidra 12.0.4 Public)
- **Java 21+** (required by Ghidra 12.x)
- **An MCP Client** (Like GhidrAssist, Claude Code, or any MCP-compatible tool)

### Binary Release (Recommended)

1. **Download the latest release**:
   - Go to the [Releases page](https://github.com/amarce/GhidrAssistMCP/releases)
   - Download the latest `.zip` file

2. **Install the extension**:
   - In Ghidra: **File -> Install Extensions -> Add Extension**
   - Select the downloaded ZIP file
   - Restart Ghidra when prompted

3. **Enable the plugin**:
   - **File -> Configure -> Configure Plugins**
   - Search for "GhidrAssistMCP"
   - Check the box to enable the plugin

### Building from Source

1. **Clone the repository**:

   ```bash
   git clone https://github.com/amarce/GhidrAssistMCP.git
   cd GhidrAssistMCP
   ```

2. **Point Gradle at your Ghidra install**:
   - Set `GHIDRA_INSTALL_DIR` (environment variable), or pass `-PGHIDRA_INSTALL_DIR=<path>` when you run Gradle.

3. **Build + install**:

   Ensure Ghidra isn't running and run:

   ```bash
   gradle installExtension
   ```

   This copies the built ZIP into your Ghidra install (`[GHIDRA_INSTALL_DIR]/Extensions/Ghidra`) and extracts it into your Ghidra **user** Extensions folder (replacing any existing extracted copy).

   If you need to override that location, pass `-PGHIDRA_USER_EXTENSIONS_DIR=<path>`.

4. **Restart / verify**:
   - Restart Ghidra.
   - If the plugin doesn't appear, enable it via **File -> Configure -> Configure Plugins** (search for "GhidrAssistMCP").

## Configuration

### Initial Setup

1. **Open the Control Panel**:
   - Window -> GhidrAssistMCP (or use the toolbar icon)

2. **Configure Server Settings**:
   - **Host**: Default is `localhost`
   - **Port**: Default is `8080`
   - **Enable/Disable**: Toggle the MCP server on/off
   - **Auth Mode**:
     - `none`: no authentication (recommended only for trusted local/dev setups)
     - `basic`: HTTP Basic auth with username/password
     - `oauth`: JWT Bearer token validation for an external authorization server

3. **OAuth mode fields are resource-server validation settings**:
   - **Issuer**: expected `iss` claim and authorization server identifier.
   - **JWKS URL**: signing keys endpoint used to verify token signatures (optional if discoverable from issuer metadata).
   - **Audience**: expected `aud` claim value.
   - **Required Scope** (optional): required scope value in token `scope`/`scp` claim.

4. **ChatGPT connector callback/redirect setup is separate from resource-server metadata**:
   - **Callback ID (optional in the UI)** should match the callback identifier shown in ChatGPT app/connector management.
   - Do **not** reuse Auth0 audience/scope values for this callback field.

### Deployment behind a reverse proxy

When your MCP server is published through Nginx/Caddy/Cloudflare (or any TLS terminator), the external URL is often different from the local bind address (`http://localhost:8080`).

- Set **Public Base URL** in OAuth settings to your externally reachable origin.
- If you cannot set a fixed public URL, enable **Trust X-Forwarded-* headers for discovery URLs**.

### Tool Management

The Configuration tab allows you to:

- **View all available tools** (59 total)
- **Enable/disable individual tools** using checkboxes
- **Save configuration** to persist across sessions
- **Monitor tool status** in real-time

## Available Tools

GhidrAssistMCP provides 59 tools organized into categories.

### Program & Data Listing

| Tool | Description |
| ---- | ----------- |
| `get_program_info` | Get basic program information (name, architecture, compiler, etc.) |
| `list_programs` | List all open programs across all CodeBrowser windows |
| `list_functions` | List functions with optional pattern filtering and pagination |
| `list_data` | List data definitions in the program |
| `list_data_types` | List all available data types |
| `list_strings` | List string references with optional filtering |
| `list_imports` | List imported functions/symbols |
| `list_exports` | List exported functions/symbols |
| `list_segments` | List memory segments |
| `list_namespaces` | List namespaces in the program |
| `list_relocations` | List relocation entries |

### Project Management

| Tool | Description |
| ---- | ----------- |
| `get_project_info` | Get project name, location, file/folder counts, and open programs |
| `list_project_files` | Browse project tree — list files and folders at a given path |
| `create_project_folder` | Create new folders in the project |
| `import_file` | Import a binary from disk into the project (auto-detects format) |
| `delete_project_file` | Delete a file from the project (destructive, requires confirmation) |
| `open_program` | Open a project file in the CodeBrowser |
| `close_program` | Close an open program (all programs can be closed — server stays active) |
| `save_project` | Save one or all open programs |
| `rename_project_item` | Rename files or folders in the project |
| `move_project_file` | Move files between project folders |

### Function & Code Analysis

| Tool | Description |
| ---- | ----------- |
| `get_function_info` | Get detailed function information (signature, variables, etc.) |
| `get_current_function` | Get function at current cursor position |
| `get_current_address` | Get current cursor address |
| `get_hexdump` | Get hexdump of memory at specific address |
| `get_bytes` | Get raw bytes from memory |
| `disassemble_range` | Disassemble raw instruction ranges even outside defined functions |
| `evaluate_expression` | Evaluate register/expression values at an address |
| `get_call_graph` | Get call graph for a function (callers and callees) |
| `get_basic_blocks` | Get basic block information for a function |

### Autopilot Tools

| Tool | Description |
| ---- | ----------- |
| `analyze_program` | Run Ghidra auto-analysis on a program (background) |
| `export_program` | Export program to binary, C/C++ header, or Intel HEX format |
| `undo_redo` | Undo or redo operations with multi-step support |
| `go_to_address` | Navigate listing view to a hex address or symbol name |

### Consolidated Tools

These tools bundle related operations behind a discriminator parameter (e.g., `action`, `target`, `target_type`, or `format`).

#### `get_code` - Code Retrieval Tool

| Parameter | Values | Description |
| --------- | ------ | ----------- |
| `format` | `decompiler`, `disassembly`, `pcode` | Output format |
| `raw` | boolean | Only affects `format: "pcode"` |
| `auto_analyze` | boolean | Optional: run auto-analysis before producing output |
| `memory_zones` | array | Optional per-request zones for memory context |

#### `class` - Class Operations Tool

| Action | Description |
| ------ | ----------- |
| `list` | List classes with optional pattern filtering and pagination |
| `get_info` | Get detailed class information (methods, fields, vtables) |

#### `xrefs` - Cross-Reference Tool

| Parameter | Description |
| --------- | ----------- |
| `address` | Find all references to/from a specific address |
| `function` | Find all cross-references for a function |

#### `struct` - Structure Operations Tool

| Action | Description |
| ------ | ----------- |
| `create` | Create a new structure from C definition or empty |
| `modify` | Modify an existing structure with new C definition |
| `merge` | Merge fields from a C definition onto an existing structure |
| `set_field` | Set/insert a single field at a specific offset |
| `name_gap` | Convert undefined bytes at an offset into a named field |
| `auto_create` | Automatically create structure from variable usage patterns |
| `rename_field` | Rename a field within a structure |
| `field_xrefs` | Find cross-references to a specific struct field |

#### `rename_symbol` - Symbol Renaming Tool

| Parameter | Values | Description |
| --------- | ------ | ----------- |
| `target_type` | `function`, `data`, `variable` | What kind of symbol to rename |

#### `set_comment` - Comment Tool

| Parameter | Values | Description |
| --------- | ------ | ----------- |
| `target` | `function`, `address` | Where to set the comment |
| `comment_type` | `eol`, `pre`, `post`, `plate`, `repeatable` | Comment type |

#### `bookmarks` - Bookmark Management Tool

| Action | Description |
| ------ | ----------- |
| `list` | List all bookmarks |
| `add` | Add a new bookmark |
| `delete` | Delete a bookmark |

#### `analysis_tasks` - Analysis Orchestration Tool

| Action | Description |
| ------ | ----------- |
| `auto_analyze` | Trigger Ghidra auto-analysis for the target program |
| `set_memory_zones` | Configure custom memory zones |
| `list_memory_zones` | List configured memory zones |
| `clear_memory_zones` | Remove all configured memory zones |

### Type & Prototype Tools

| Tool | Description |
| ----- | ----------- |
| `get_data_type` | Get detailed data type information and structure definitions |
| `delete_data_type` | Delete a data type by name |
| `set_data_type` | Set data type at a specific address |
| `set_function_prototype` | Set function signature/prototype |
| `set_local_variable_type` | Set data type for local variables |

### Binary & Function Mutation Tools

| Tool | Description |
| ----- | ----------- |
| `function_lifecycle` | Create, delete, or redefine functions by address/body range |
| `patch_bytes` | Patch bytes in writable memory with optional dry-run |
| `assemble_at` | Assemble instructions at a specific address |
| `clear_code` | Clear code at a specific address |
| `create_function_at` | Create a function at a specific address |
| `reanalyze_range` | Reanalyze a specific address range |
| `rename_symbol_batch` | Batch rename multiple symbols |

### Scripting Tools

| Tool | Description |
| ----- | ----------- |
| `run_script` | Executes inline Python/Java Ghidra scripts against the current program |

### Search Tools

| Tool | Description |
| ----- | ----------- |
| `search_bytes` | Search for byte patterns in memory |

### Async Task Management

| Tool | Description |
| ---- | ----------- |
| `get_task_status` | Check status and retrieve results of async tasks |
| `cancel_task` | Cancel a running async task |
| `list_tasks` | List all pending/running/completed tasks |

## MCP Resources

GhidrAssistMCP exposes 5 static resources that can be read by MCP clients:

| Resource URI | Description |
| ------------ | ----------- |
| `ghidra://program/info` | Basic program information |
| `ghidra://program/functions` | List of all functions |
| `ghidra://program/strings` | String references |
| `ghidra://program/imports` | Imported symbols |
| `ghidra://program/exports` | Exported symbols |

## MCP Prompts

Pre-built prompts for common analysis tasks:

| Prompt | Description |
| ------ | ----------- |
| `analyze_function` | Comprehensive function analysis prompt |
| `identify_vulnerability` | Security vulnerability identification |
| `document_function` | Generate function documentation |
| `trace_data_flow` | Data flow analysis prompt |
| `trace_network_data` | Trace network send/recv call stacks |

## Usage Examples

### Project Management (No Program Required)

```json
{
  "method": "tools/call",
  "params": {
    "name": "list_project_files",
    "arguments": { "folder_path": "/" }
  }
}
```

### Import a Binary

```json
{
  "method": "tools/call",
  "params": {
    "name": "import_file",
    "arguments": {
      "file_path": "/path/to/binary.exe",
      "folder_path": "/malware"
    }
  }
}
```

### Open and Analyze

```json
{
  "method": "tools/call",
  "params": {
    "name": "open_program",
    "arguments": { "file_path": "/malware/binary.exe" }
  }
}
```

```json
{
  "method": "tools/call",
  "params": {
    "name": "analyze_program"
  }
}
```

### Decompile Function

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_code",
    "arguments": {
      "function": "main",
      "format": "decompiler"
    }
  }
}
```

### Navigate and Inspect

```json
{
  "method": "tools/call",
  "params": {
    "name": "go_to_address",
    "arguments": { "address": "main" }
  }
}
```

### Export and Save

```json
{
  "method": "tools/call",
  "params": {
    "name": "export_program",
    "arguments": {
      "output_path": "/tmp/patched.bin",
      "format": "binary"
    }
  }
}
```

```json
{
  "method": "tools/call",
  "params": {
    "name": "save_project"
  }
}
```

### Undo/Redo

```json
{
  "method": "tools/call",
  "params": {
    "name": "undo_redo",
    "arguments": { "action": "undo", "count": 3 }
  }
}
```

### Multi-Program Support

When working with multiple open programs, first list them:

```json
{
  "method": "tools/call",
  "params": { "name": "list_programs" }
}
```

Then specify which program to target using `program_name`:

```json
{
  "method": "tools/call",
  "params": {
    "name": "list_functions",
    "arguments": {
      "program_name": "target_binary.exe",
      "limit": 10
    }
  }
}
```

## Multi-Window Support & Active Context Awareness

GhidrAssistMCP uses a singleton architecture that enables seamless operation across multiple CodeBrowser windows:

### How It Works

1. **Single Shared Server**: One MCP server (port 8080) serves all CodeBrowser windows
2. **Focus Tracking**: Automatically detects which CodeBrowser window is currently active
3. **Context Hints**: All tool responses include context information to help AI understand which binary is in focus
4. **Early Start**: Server starts before any program is loaded — project management tools work immediately

### Context Information in Responses

Every tool response includes a context header:

```plaintext
[Context] Operating on: malware.exe | Active window: malware.exe

<tool response content>
```

## Architecture

### Core Components

```plaintext
GhidrAssistMCP/
├── GhidrAssistMCPManager     # Singleton coordinator for multi-window support
│   ├── Tracks all CodeBrowser windows
│   ├── Manages focus tracking
│   └── Owns shared server and backend
├── GhidrAssistMCPPlugin      # Plugin instance (extends Plugin, not ProgramPlugin)
│   ├── Registers with singleton manager
│   ├── Handles program events via processEvent()
│   └── Server starts immediately in init()
├── GhidrAssistMCPServer      # HTTP MCP server (SSE + Streamable)
│   └── Single shared instance on port 8080
├── GhidrAssistMCPBackend     # Tool management and execution
│   ├── Tool registry with enable/disable states (59 tools)
│   ├── Result caching system
│   ├── Async task management
│   └── Resource and prompt registries
├── GhidrAssistMCPProvider    # UI component provider
│   └── First registered instance provides UI
├── cache/                    # Caching infrastructure
├── tasks/                    # Async task management
├── resources/                # MCP Resources (5 total)
├── prompts/                  # MCP Prompts (5 total)
└── tools/                    # MCP Tools (59 total)
    ├── Program & data listing tools (11)
    ├── Project management tools (10)
    ├── Function & code analysis tools (9)
    ├── Autopilot tools (4)
    ├── Consolidated action-based tools (8)
    ├── Type & prototype tools (5)
    ├── Binary & function mutation tools (7)
    ├── Scripting tools (1)
    ├── Search tools (1)
    └── Async task management tools (3)
```

### Tool Design Patterns

**Consolidated Tools**: Related operations are consolidated into single tools with a discriminator parameter:

- `get_code`: `format: decompiler|disassembly|pcode`
- `class`: `action: list|get_info`
- `struct`: `action: create|modify|auto_create|rename_field|field_xrefs`
- `rename_symbol`: `target_type: function|data|variable`
- `set_comment`: `target: function|address`
- `bookmarks`: `action: list|add|delete`

**Tool Interface Methods**:

- `isReadOnly()`: Indicates if tool modifies program state
- `isLongRunning()`: Triggers async execution with task management
- `isCacheable()`: Enables result caching for repeated queries
- `isDestructive()`: Marks potentially dangerous operations
- `isIdempotent()`: Indicates if repeated calls produce same result

### MCP Protocol Implementation

- **Transports**:
  - HTTP with Server-Sent Events (SSE)
  - Streamable HTTP
- **Endpoints**:
  - `GET /sse` - SSE connection for bidirectional communication
  - `POST /message` - Message exchange endpoint
  - `GET /mcp` - Receive Streamable HTTP events
  - `POST /mcp` - Initialize Streamable HTTP session
  - `DELETE /mcp` - Terminate Streamable HTTP session
- **Capabilities**: Tools, Resources, Prompts

## Development

### Adding New Tools

1. **Implement McpTool interface**:

   ```java
   public class MyCustomTool implements McpTool {
       @Override
       public String getName() { return "my_custom_tool"; }

       @Override
       public String getDescription() { return "Description"; }

       @Override
       public McpSchema.JsonSchema getInputSchema() { /* ... */ }

       @Override
       public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
           // Implementation
       }

       // For tools that need project/backend access:
       @Override
       public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
           PluginTool tool = backend.getPluginTool();
           Project project = tool.getProject();
           // ...
       }
   }
   ```

2. **Register in backend**:

   ```java
   // In GhidrAssistMCPBackend constructor
   registerTool(new MyCustomTool());
   ```

### Build Commands

```bash
# Clean build
gradle clean

# Build extension zip (written to dist/)
gradle buildExtension

# Install extension into the Ghidra user Extensions directory
gradle installExtension

# Uninstall
gradle uninstallExtension

# Build with specific Ghidra path
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

### Dependencies

- **MCP SDK**: `io.modelcontextprotocol.sdk:mcp:0.17.1`
- **Jetty Server**: `11.0.20` (HTTP/SSE transport)
- **Jackson**: `2.18.3` (JSON processing)
- **Ghidra API**: Bundled with Ghidra installation (11.4+ / 12.x)

## Troubleshooting

### Common Issues

#### Server Won't Start

- Check if port 8080 is available
- Verify Ghidra installation path
- Examine console logs for errors

#### Tools Not Appearing

- Ensure plugin is enabled
- Check Configuration tab for tool status
- Verify backend initialization in logs

#### MCP Client Connection Issues

- Confirm server is running (check GhidrAssistMCP window)
- Test connection: `curl http://localhost:8080/sse`
- Check firewall settings

#### Tool Execution Failures

- Some tools require an open program — check the tool description
- Project management tools work without any program loaded
- Check tool parameters are correct
- Review error messages in Log tab

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper tests
4. **Follow code style**: Use existing patterns and conventions
5. **Submit a pull request** with detailed description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **NSA/Ghidra Team** for the excellent reverse engineering platform
- **Anthropic** for the Model Context Protocol specification
- **[symgraph/GhidrAssistMCP](https://github.com/symgraph/GhidrAssistMCP)** — original upstream project by [jtang613](https://github.com/jtang613)

---

**Questions or Issues?**

Please open an issue on the [project repository](https://github.com/amarce/GhidrAssistMCP/issues) for bug reports, feature requests, or questions about usage and development.
