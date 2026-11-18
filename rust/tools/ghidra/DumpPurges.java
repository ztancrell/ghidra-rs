// Post-script: one line per function: entry, purge, thunked entry (or -), body min, body max,
// address count, no-return. Arguments: output path.
//@category Mercs2
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DumpPurges extends GhidraScript {
    @Override
    public void run() throws Exception {
        try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isExternal()) continue;
                Function t = f.getThunkedFunction(false);
                out.println(f.getEntryPoint() + " " + f.getStackPurgeSize() + " "
                    + (t == null ? "-" : t.getEntryPoint().toString()) + " "
                    + f.getBody().getMinAddress() + " " + f.getBody().getMaxAddress() + " "
                    + f.getBody().getNumAddresses() + " " + f.hasNoReturn());
            }
        }
    }
}
