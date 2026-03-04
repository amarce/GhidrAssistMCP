package ghidra.app.script;

import ghidra.program.model.listing.Program;

public class GhidraState {
    private Object currentProgram;

    public GhidraState() {
    }

    public GhidraState(Object tool, Object project, Program program, Object location, Object selection, Object highlight) {
        if (program != null && tool == null) {
            throw new NullPointerException("tool");
        }
        currentProgram = program;
    }

    public Object getCurrentProgram() {
        return currentProgram;
    }
}
