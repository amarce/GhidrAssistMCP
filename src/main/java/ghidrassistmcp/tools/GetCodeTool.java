/*
 * MCP tool for getting code representation of a function.
 * Consolidates decompile_function, disassemble_function, and get_pcode into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets code representation of a function in various formats.
 * Replaces separate decompile_function, disassemble_function, and get_pcode tools.
 */
public class GetCodeTool implements McpTool {

    @Override
    public boolean isLongRunning() {
        // Decompiler and pcode formats require decompilation
        return true;
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public boolean supportsAsync() {
        return true;
    }

    @Override
    public String getName() {
        return "get_code";
    }

    @Override
    public String getDescription() {
        return "Get code representation of a function in various formats (decompiler, disassembly, or pcode)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "function", Map.of(
                    "type", "string",
                    "description", "Function identifier (name, qualified name like Namespace::Func, or address like 0x401000)"
                ),
                "format", Map.of(
                    "type", "string",
                    "description", "Output format for the requested function",
                    "enum", List.of("decompiler", "disassembly", "pcode")
                ),
                "raw", Map.of(
                    "type", "boolean",
                    "description", "Optional: Only affects format 'pcode' (raw pcode ops vs grouped by basic blocks)",
                    "default", false
                ),
                "auto_analyze", Map.of(
                    "type", "boolean",
                    "description", "Optional: run auto-analysis before decompilation/disassembly for fresher results",
                    "default", false
                ),
                "memory_zones", Map.of(
                    "type", "array",
                    "description", "Optional additional memory zones to include in output context",
                    "items", Map.of(
                        "type", "object",
                        "properties", Map.of(
                            "start", Map.of("type", "string"),
                            "end", Map.of("type", "string"),
                            "label", Map.of("type", "string")
                        ),
                        "required", List.of("start", "end")
                    )
                )
            ),
            List.of("function", "format"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String functionIdentifier = (String) arguments.get("function");
        String format = (String) arguments.get("format");
        boolean raw = Boolean.TRUE.equals(arguments.get("raw"));
        boolean autoAnalyze = Boolean.TRUE.equals(arguments.get("auto_analyze"));

        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function parameter is required")
                .build();
        }

        if (format == null || format.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("format parameter is required (decompiler, disassembly, or pcode)")
                .build();
        }

        format = format.toLowerCase();
        if (!format.equals("decompiler") && !format.equals("disassembly") && !format.equals("pcode")) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid format. Use 'decompiler', 'disassembly', or 'pcode'")
                .build();
        }

        if (autoAnalyze && backend != null) {
            String analysisResult = backend.runAutoAnalysis(currentProgram, "get_code:" + functionIdentifier + ":" + format);
            if (analysisResult != null && !analysisResult.isEmpty()) {
                // continue execution; analysis failures are reported in output footer
                arguments = new java.util.HashMap<>(arguments);
                arguments.put("_auto_analyze_result", analysisResult);
            }
        }

        // Find the function
        Function function = findFunction(currentProgram, functionIdentifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionIdentifier)
                .build();
        }

        McpSchema.CallToolResult base;
        switch (format) {
            case "decompiler":
                base = getDecompiledCode(currentProgram, function);
                break;
            case "disassembly":
                base = getDisassemblyCode(currentProgram, function);
                break;
            case "pcode":
                base = getPcodeRepresentation(currentProgram, function, raw);
                break;
            default:
                base = McpSchema.CallToolResult.builder().addTextContent("Unknown format: " + format).build();
        }

        return appendMemoryZoneContext(base, arguments, currentProgram, backend);
    }

    private McpSchema.CallToolResult appendMemoryZoneContext(McpSchema.CallToolResult base,
            Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        if (base == null || base.content() == null || base.content().isEmpty() ||
            !(base.content().get(0) instanceof McpSchema.TextContent first)) {
            return base;
        }

        List<GhidrAssistMCPBackend.MemoryZone> zones = new ArrayList<>();
        if (backend != null) {
            zones.addAll(backend.getCustomMemoryZones(program));
        }
        zones.addAll(parseMemoryZonesArg(arguments, program));

        StringBuilder appendix = new StringBuilder();
        Object analysis = arguments.get("_auto_analyze_result");
        if (analysis instanceof String) {
            appendix.append("\n\n## Auto Analysis\n").append((String) analysis);
        }

        if (!zones.isEmpty()) {
            appendix.append("\n\n## Memory Zone Context\n");
            for (GhidrAssistMCPBackend.MemoryZone zone : zones) {
                appendix.append("- ").append(zone.label()).append(": ")
                    .append(zone.start()).append(" -> ").append(zone.end());
                String bytes = readZoneBytes(program, zone, 96);
                if (bytes != null) {
                    appendix.append("\n  bytes: ").append(bytes);
                }
                appendix.append("\n");
            }
        }

        if (appendix.length() == 0) {
            return base;
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(first.text() + appendix)
            .build();
    }

    private List<GhidrAssistMCPBackend.MemoryZone> parseMemoryZonesArg(Map<String, Object> arguments, Program program) {
        List<GhidrAssistMCPBackend.MemoryZone> zones = new ArrayList<>();
        Object memoryZonesObj = arguments.get("memory_zones");
        if (!(memoryZonesObj instanceof List<?> list)) {
            return zones;
        }

        int index = 0;
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> rawMap)) {
                index++;
                continue;
            }
            Address start = parseAddressFromObject(program, rawMap.get("start"));
            Address end = parseAddressFromObject(program, rawMap.get("end"));
            if (start == null || end == null || start.compareTo(end) > 0) {
                index++;
                continue;
            }
            Object labelObj = rawMap.get("label");
            String label = labelObj instanceof String && !((String) labelObj).isBlank()
                ? (String) labelObj : "request_zone_" + index;
            zones.add(new GhidrAssistMCPBackend.MemoryZone(start.toString(), end.toString(), label));
            index++;
        }

        return zones;
    }

    private Address parseAddressFromObject(Program program, Object value) {
        if (value instanceof String s) {
            return program.getAddressFactory().getAddress(s);
        }
        return null;
    }

    private String readZoneBytes(Program program, GhidrAssistMCPBackend.MemoryZone zone, int maxBytes) {
        Address start = program.getAddressFactory().getAddress(zone.start());
        Address end = program.getAddressFactory().getAddress(zone.end());
        if (start == null || end == null || start.compareTo(end) > 0) {
            return null;
        }

        long total = end.subtract(start) + 1;
        int length = (int) Math.min(Math.max(total, 0), maxBytes);
        if (length <= 0) {
            return null;
        }

        byte[] data = new byte[length];
        try {
            program.getMemory().getBytes(start, data);
        } catch (MemoryAccessException e) {
            return "<unreadable: " + e.getMessage() + ">";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02X", data[i] & 0xff));
            if (i < data.length - 1) {
                sb.append(' ');
            }
        }
        if (total > maxBytes) {
            sb.append(" ...");
        }
        return sb.toString();
    }

    /**
     * Get decompiled C-like code for a function.
     */
    private McpSchema.CallToolResult getDecompiledCode(Program program, Function function) {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(function.getProgram());

            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (results.isTimedOut()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation timed out for function: " + function.getName())
                    .build();
            }

            if (results.isValid() == false) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation error for function " + function.getName() + ": " + results.getErrorMessage())
                    .build();
            }

            String decompiledCode = results.getDecompiledFunction().getC();

            if (decompiledCode == null || decompiledCode.trim().isEmpty()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No decompiled code available for function: " + function.getName())
                    .build();
            }

            return McpSchema.CallToolResult.builder()
                .addTextContent(decompiledCode)
                .build();

        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Get disassembly for a function.
     */
    private McpSchema.CallToolResult getDisassemblyCode(Program program, Function function) {
        StringBuilder result = new StringBuilder();
        result.append("Disassembly for: ").append(function.getName())
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
        int instructionCount = 0;

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            result.append(instruction.getAddress()).append(" ");
            result.append(String.format("%-8s", instruction.getMnemonicString()));

            // Add operands
            int numOperands = instruction.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                if (i == 0) {
                    result.append(" ");
                } else {
                    result.append(", ");
                }
                result.append(instruction.getDefaultOperandRepresentation(i));
            }

            // Add any comments
            String comment = instruction.getComment(CommentType.EOL);
            if (comment != null && !comment.trim().isEmpty()) {
                result.append(" ; ").append(comment.trim());
            }

            result.append("\n");
            instructionCount++;
        }

        result.append("\nTotal instructions: ").append(instructionCount);

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Get P-Code representation for a function.
     */
    private McpSchema.CallToolResult getPcodeRepresentation(Program program, Function function, boolean raw) {
        StringBuilder result = new StringBuilder();
        result.append("P-Code for: ").append(function.getName())
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (!results.decompileCompleted()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation failed for function: " + function.getName())
                    .build();
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Could not get high function for: " + function.getName())
                    .build();
            }

            // Get P-Code operations
            if (raw) {
                // Raw P-Code from high function
                result.append("## Raw P-Code Operations:\n```\n");
                Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST op = ops.next();
                    result.append(op.getSeqnum().getTarget()).append(": ")
                          .append(op.toString()).append("\n");
                }
                result.append("```\n");
            } else {
                // P-Code organized by basic blocks
                result.append("## P-Code by Basic Blocks:\n\n");
                var blocks = highFunction.getBasicBlocks();

                for (var block : blocks) {
                    if (block instanceof PcodeBlockBasic basicBlock) {
                        result.append("### Block ").append(basicBlock.getIndex())
                              .append(" @ ").append(basicBlock.getStart()).append("\n");
                        result.append("```\n");

                        Iterator<PcodeOp> blockOps = basicBlock.getIterator();
                        while (blockOps.hasNext()) {
                            PcodeOp op = blockOps.next();
                            result.append("  ").append(op.toString()).append("\n");
                        }
                        result.append("```\n\n");
                    }
                }
            }

            // Add summary
            result.append("## Summary:\n");
            result.append("- Function: ").append(function.getName()).append("\n");
            result.append("- Entry: ").append(function.getEntryPoint()).append("\n");

            var blocks = highFunction.getBasicBlocks();
            result.append("- Basic Blocks: ").append(blocks.size()).append("\n");

        } finally {
            decompiler.dispose();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Find a function by name or address.
     * Supports C++ qualified names (e.g., "Class::method" or "Outer::Inner::method").
     */
    private Function findFunction(Program program, String identifier) {
        // Try to parse as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                // Try to get function at the address
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;

                // If not found at address, try containing function
                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not an address, try as function name
        }

        // Check if this is a qualified name (contains ::)
        if (identifier.contains("::")) {
            String[] parts = identifier.split("::");
            if (parts.length >= 2) {
                String simpleName = parts[parts.length - 1];
                String[] namespaceParts = new String[parts.length - 1];
                System.arraycopy(parts, 0, namespaceParts, 0, parts.length - 1);

                // Search for exact namespace match
                Function match = findFunctionByQualifiedName(program, simpleName, namespaceParts);
                if (match != null) {
                    return match;
                }
            }
        }

        // Fall back to simple name search
        FunctionIteratorWrapper funcs = new FunctionIteratorWrapper(program.getFunctionManager().getFunctions(true));
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (func.getName().equals(identifier)) {
                return func;
            }
        }

        return null;
    }

    private Function findFunctionByQualifiedName(Program program, String functionName, String[] namespaceParts) {
        FunctionIteratorWrapper funcs = new FunctionIteratorWrapper(program.getFunctionManager().getFunctions(true));
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (!func.getName().equals(functionName)) {
                continue;
            }

            if (namespaceMatches(func.getParentNamespace(), namespaceParts)) {
                return func;
            }
        }
        return null;
    }

    private boolean namespaceMatches(Namespace namespace, String[] expectedParts) {
        if (expectedParts.length == 0) {
            return namespace == null;
        }

        int index = expectedParts.length - 1;
        Namespace current = namespace;

        while (index >= 0 && current != null) {
            String expected = expectedParts[index];
            String actual = current.getName();
            if (!expected.equals(actual)) {
                return false;
            }
            current = current.getParentNamespace();
            index--;
        }

        return index < 0;
    }

    /**
     * Wrapper to avoid directly exposing Ghidra FunctionIterator type in method signatures.
     */
    private static class FunctionIteratorWrapper {
        private final java.util.Iterator<Function> iterator;

        FunctionIteratorWrapper(java.util.Iterator<Function> iterator) {
            this.iterator = iterator;
        }

        boolean hasNext() {
            return iterator.hasNext();
        }

        Function next() {
            return iterator.next();
        }
    }
}
