package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class CreateFunctionAtTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isDestructive() { return true; }

    @Override
    public String getName() { return "create_function_at"; }

    @Override
    public String getDescription() { return "Create a function at an entry address and return resulting function range"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "entry", Map.of("type", "string", "description", "Function entry address"),
            "name", Map.of("type", "string", "description", "Optional function name")
        ), List.of("entry"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        ObjectNode response = objectMapper.createObjectNode();
        response.put("tool", getName());

        if (currentProgram == null) {
            response.put("success", false);
            response.put("error", "No program currently loaded");
            return result(response);
        }

        String entryStr = getString(arguments, "entry");
        String name = getString(arguments, "name");
        if (entryStr == null) {
            response.put("success", false);
            response.put("error", "entry is required");
            return result(response);
        }

        Address entry = currentProgram.getAddressFactory().getAddress(entryStr);
        if (entry == null) {
            response.put("success", false);
            response.put("error", "Invalid entry address: " + entryStr);
            return result(response);
        }

        int tx = currentProgram.startTransaction("Create function at address");
        boolean commit = false;
        try {
            boolean created = false;
            boolean renamed = false;
            boolean existingHadNonEmptyBody = false;

            Instruction instructionAtEntry = currentProgram.getListing().getInstructionAt(entry);
            if (instructionAtEntry == null) {
                AddressSet disassemblyBounds = boundedDisassemblySet(entry);
                DisassembleCommand disassembleCmd = new DisassembleCommand(entry, disassemblyBounds, true);
                boolean disassembled = disassembleCmd.applyTo(currentProgram);
                instructionAtEntry = currentProgram.getListing().getInstructionAt(entry);
                if (!disassembled || instructionAtEntry == null) {
                    response.put("success", false);
                    response.put("created", false);
                    response.put("renamed", false);
                    response.put("instruction_count", 0);
                    response.putNull("body_range");
                    response.put("error", "Unable to disassemble instruction at entry; ensure bytes are defined and analyzable");
                    return result(response);
                }
            }

            Function existing = currentProgram.getFunctionManager().getFunctionAt(entry);
            Function function;
            if (existing != null) {
                function = existing;
                existingHadNonEmptyBody = hasInstructions(function, currentProgram);
                if (name != null && !name.isBlank()) {
                    String previousName = function.getName();
                    function.setName(name, SourceType.USER_DEFINED);
                    renamed = !name.equals(previousName);
                }
            } else {
                CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(name, entry, null, SourceType.USER_DEFINED);
                created = createFunctionCmd.applyTo(currentProgram);
                function = currentProgram.getFunctionManager().getFunctionAt(entry);
            }

            if (function == null) {
                response.put("success", false);
                response.put("created", created);
                response.put("renamed", renamed);
                response.put("instruction_count", 0);
                response.putNull("body_range");
                response.put("error", "Unable to create function at entry");
            } else {
                long instructionCount = countInstructions(function, currentProgram);
                String bodyRange = getBodyRange(function.getBody());
                if (instructionCount == 0) {
                    response.put("success", false);
                    response.put("created", created);
                    response.put("renamed", renamed);
                    response.put("existing_had_non_empty_body", existingHadNonEmptyBody);
                    response.put("instruction_count", 0);
                    response.putNull("body_range");
                    response.put("error", "Function body contains no instructions; run disassembly/analysis before function creation");
                    return result(response);
                }

                commit = created || renamed;
                response.put("success", true);
                response.put("program", currentProgram.getName());
                response.put("entry", function.getEntryPoint().toString());
                response.put("name", function.getName());
                response.put("range", function.getBody().toString());
                response.put("created", created);
                response.put("renamed", renamed);
                response.put("existing_had_non_empty_body", existingHadNonEmptyBody);
                response.put("instruction_count", instructionCount);
                response.put("body_range", bodyRange);
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "Failed creating function: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }

        return result(response);
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    private static AddressSet boundedDisassemblySet(Address entry) {
        try {
            return new AddressSet(entry, entry.addNoWrap(0x1000));
        } catch (Exception e) {
            return new AddressSet(entry);
        }
    }

    private static long countInstructions(Function function, Program program) {
        if (function == null || function.getBody() == null || function.getBody().isEmpty()) {
            return 0;
        }

        long count = 0;
        ghidra.program.model.listing.InstructionIterator instructionIterator =
            program.getListing().getInstructions(function.getBody(), true);
        while (instructionIterator.hasNext()) {
            instructionIterator.next();
            count++;
        }
        return count;
    }

    private static boolean hasInstructions(Function function, Program program) {
        return countInstructions(function, program) > 0;
    }

    private static String getBodyRange(AddressSetView body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        return body.getMinAddress() + "-" + body.getMaxAddress();
    }

    private McpSchema.CallToolResult result(ObjectNode response) {
        return McpSchema.CallToolResult.builder().addTextContent(response.toPrettyString()).build();
    }
}
