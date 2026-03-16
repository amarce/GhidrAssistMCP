/*
 * MCP tool for navigating to a specific address in Ghidra.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that navigates Ghidra's listing view to a specific address or symbol.
 */
public class GoToAddressTool implements McpTool {

    @Override
    public String getName() {
        return "go_to_address";
    }

    @Override
    public String getDescription() {
        return "Navigate Ghidra's listing view to a specific address or symbol. " +
               "Accepts hex addresses (e.g., '0x401000') or symbol names (e.g., 'main').";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of("type", "string",
                    "description", "Address (hex, e.g., '0x401000') or symbol name (e.g., 'main')")
            ),
            List.of("address"), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No program currently loaded")
                .build();
        }

        PluginTool pluginTool = backend.getPluginTool();
        if (pluginTool == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No active Ghidra tool available")
                .build();
        }

        String addressStr = (String) arguments.get("address");
        if (addressStr == null || addressStr.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'address' is required")
                .build();
        }

        GoToService goToService = pluginTool.getService(GoToService.class);
        if (goToService == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: GoToService not available")
                .build();
        }

        // Try as hex address first
        Address addr = null;
        String cleanAddr = addressStr.trim();
        if (cleanAddr.startsWith("0x") || cleanAddr.startsWith("0X")) {
            cleanAddr = cleanAddr.substring(2);
        }

        try {
            addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(cleanAddr);
        } catch (Exception e) {
            // Not a valid hex address, try as symbol
        }

        if (addr != null) {
            boolean success = goToService.goTo(addr);
            if (success) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Navigated to address: " + addr)
                    .build();
            }
        }

        // Try as symbol name
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbols(addressStr);
        if (symbols.hasNext()) {
            Symbol sym = symbols.next();
            boolean success = goToService.goTo(sym.getAddress());
            if (success) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Navigated to symbol '" + sym.getName() + "' at " + sym.getAddress())
                    .build();
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Could not navigate to: " + addressStr +
                "\nAddress or symbol not found in " + currentProgram.getName())
            .build();
    }
}
