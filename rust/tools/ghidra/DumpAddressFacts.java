// Post-script: for each address in a list file (one hex address per line), prints one line:
// address, whether a function starts there (and its symbol's source), whether an instruction
// starts there, the function containing it, and every reference to it (type@from, with the
// function containing the source).
// Arguments: input list path, output path.
//@category Mercs2
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;

public class DumpAddressFacts extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        FunctionManager fm = currentProgram.getFunctionManager();
        try (PrintWriter out = new PrintWriter(a[1])) {
            for (String line : Files.readAllLines(Path.of(a[0]))) {
                if (line.isBlank()) continue;
                Address x = toAddr(Long.parseLong(line.trim().replaceFirst("^0x", ""), 16));
                Function at = fm.getFunctionAt(x);
                Function in = fm.getFunctionContaining(x);
                StringBuilder sb = new StringBuilder(line.trim());
                sb.append(" fn=").append(at == null ? "-" : at.getSymbol().getSource().toString());
                sb.append(" insn=").append(getInstructionAt(x) != null);
                sb.append(" in=").append(in == null ? "-" : in.getEntryPoint().toString());
                // what the byte before holds (Function Start Search's "after" checks)
                Address prev = x.previous();
                sb.append(" prev=").append(prev == null ? "-"
                    : getInstructionContaining(prev) != null ? "insn"
                    : getDataContaining(prev) != null && getDataContaining(prev).isDefined() ? "data" : "undef");
                for (Reference r : getReferencesTo(x)) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    sb.append(' ').append(r.getReferenceType()).append('@').append(r.getFromAddress())
                        .append('/').append(f == null ? "-" : f.getEntryPoint().toString());
                }
                out.println(sb);
            }
        }
    }
}
