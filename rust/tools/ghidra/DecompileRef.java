// The S10 reference: the C of mercs2-decomp's Decompile.java (DecompInterface with its default
// options, 60 s per function), written to one file per address instead of the log.
// Arguments: the output directory, then the addresses. A function that does not decompile gets
// its error message; an address without a function gets "no function at <address>".
//@category ghidra-rs
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompileRef extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File dir = new File(args[0]);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (int i = 1; i < args.length; i++) {
            Function f = getFunctionAt(toAddr(args[i]));
            String text;
            if (f == null) {
                text = "no function at " + args[i];
            }
            else {
                DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
                text = r.decompileCompleted() ? r.getDecompiledFunction().getC() : r.getErrorMessage();
            }
            Files.write(new File(dir, args[i]).toPath(), (text + "\n").getBytes(StandardCharsets.UTF_8));
        }
        decompiler.dispose();
    }
}
