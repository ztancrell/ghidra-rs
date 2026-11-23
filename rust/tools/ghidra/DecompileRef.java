// The S10 reference: the C of mercs2-decomp's Decompile.java (DecompInterface with its default
// options, 60 s per function), written to one file per address instead of the log.
// Arguments: the output directory, then the addresses. `@<file>` stands for the addresses of a
// file (the first word of each line; `#` comments) and `all` for every function of the program
// (as 0x%08x). A function that does not decompile gets its error message; an address without a
// function gets "no function at <address>". Each file is written when its function is done, and
// a line `<address> <ok|failed|timeout|nofunc> <milliseconds>` (tabs) is added to
// <output directory>.status; every 100 functions the log gets a progress line.
// With DECOMP_DEBUG_DIR set, also writes the decompiler's debug XML (DecompInterface.enableDebug)
// of each function to <dir>/<address>.xml, for decomp_dbg's `restore`.
//@category ghidra-rs
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompileRef extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File dir = new File(args[0]);
        List<String> addrs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("all")) {
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    addrs.add(String.format("0x%08x", f.getEntryPoint().getOffset()));
                }
            }
            else if (args[i].startsWith("@")) {
                for (String line : Files.readAllLines(new File(args[i].substring(1)).toPath())) {
                    String a = line.trim().split("\\s+")[0];
                    if (!a.isEmpty() && !a.startsWith("#")) {
                        addrs.add(a);
                    }
                }
            }
            else {
                addrs.add(args[i]);
            }
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        long start = System.currentTimeMillis();
        int done = 0, failed = 0, timeout = 0, nofunc = 0;
        try (BufferedWriter status = Files.newBufferedWriter(new File(dir.getPath() + ".status").toPath(),
            StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            for (String a : addrs) {
                if (monitor.isCancelled()) {
                    break;
                }
                long t = System.currentTimeMillis();
                Function f = getFunctionAt(toAddr(a));
                String text, st;
                if (f == null) {
                    text = "no function at " + a;
                    st = "nofunc";
                    nofunc++;
                }
                else {
                    String dbg = System.getenv("DECOMP_DEBUG_DIR");
                    if (dbg != null) {
                        // the debug dump needs options set (DecompileOptions' defaults)
                        decompiler.setOptions(new DecompileOptions());
                        decompiler.enableDebug(new File(dbg, a + ".xml"));
                    }
                    DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
                    if (r.decompileCompleted()) {
                        text = r.getDecompiledFunction().getC();
                        st = "ok";
                    }
                    else {
                        text = r.getErrorMessage();
                        if (r.isTimedOut()) {
                            st = "timeout";
                            timeout++;
                        }
                        else {
                            st = "failed";
                            failed++;
                        }
                    }
                }
                Files.write(new File(dir, a).toPath(), (text + "\n").getBytes(StandardCharsets.UTF_8));
                status.write(a + "\t" + st + "\t" + (System.currentTimeMillis() - t) + "\n");
                status.flush();
                if (++done % 100 == 0 || done == addrs.size()) {
                    println("DecompileRef: " + done + " / " + addrs.size() + ", timeout " + timeout +
                        ", failed " + failed + ", no function " + nofunc + ", " +
                        (System.currentTimeMillis() - start) / 1000 + " s");
                }
            }
        }
        decompiler.dispose();
    }
}
