// Pre-script: wraps every auto-analysis analyzer so each added()/removed() call is logged with its
// address set (size, ranges, whether it holds the watched addresses) and the functions it made or
// removed (diff of the function entry set around the call; changes made between two analyzer calls,
// by the queued commands such as disassembly and CreateFunctionCmd, are logged as "between").
// Arguments: output log path, then the watched addresses (hex).
//@category Mercs2
import ghidra.app.plugin.core.analysis.AnalysisScheduler;
import ghidra.app.plugin.core.analysis.AnalysisTaskList;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class TraceFunctions extends GhidraScript {
    PrintWriter out;
    final List<Address> watch = new ArrayList<>();
    final Set<Address> known = new TreeSet<>();
    int seq = 0;
    final java.util.Map<Address, String> last = new java.util.HashMap<>();

    @Override
    @SuppressWarnings("unchecked")
    public void run() throws Exception {
        String[] a = getScriptArgs();
        out = new PrintWriter(new java.io.FileWriter(a[0]), true);
        for (int i = 1; i < a.length; i++) {
            watch.add(currentProgram.getAddressFactory().getAddress(a[i]));
        }
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Field arr = AutoAnalysisManager.class.getDeclaredField("taskArray");
        arr.setAccessible(true);
        Field tasks = AnalysisTaskList.class.getDeclaredField("tasks");
        tasks.setAccessible(true);
        Field an = AnalysisScheduler.class.getDeclaredField("analyzer");
        an.setAccessible(true);
        int wrapped = 0;
        for (AnalysisTaskList list : (AnalysisTaskList[]) arr.get(mgr)) {
            for (AnalysisScheduler s : (List<AnalysisScheduler>) tasks.get(list)) {
                Analyzer real = (Analyzer) an.get(s);
                an.set(s, (Analyzer) Proxy.newProxyInstance(Analyzer.class.getClassLoader(),
                    new Class[] {Analyzer.class}, (proxy, m, args) -> {
                        boolean trace = m.getName().equals("added") || m.getName().equals("removed");
                        if (trace) before(real, m.getName(), (AddressSetView) args[1]);
                        try {
                            return m.invoke(real, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        } finally {
                            if (trace) after(real, m.getName());
                        }
                    }));
                wrapped++;
            }
        }
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            known.add(f.getEntryPoint());
        }
        log("wrapped " + wrapped + " analyzers; watch " + watch);
    }

    void log(String s) {
        out.println(s);
    }

    void diff(String who) {
        Set<Address> now = new TreeSet<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) now.add(it.next().getEntryPoint());
        for (Address x : now) if (!known.contains(x)) log("FUNC+ " + x + " by " + who);
        for (Address x : known) if (!now.contains(x)) log("FUNC- " + x + " by " + who);
        known.clear();
        known.addAll(now);
    }

    void before(Analyzer an, String m, AddressSetView set) {
        if (currentProgram.getFunctionManager().getFunctionCount() != known.size()) {
            diff("between (before #" + seq + " " + an.getName() + ")");
        }
        seq++;
        StringBuilder sb = new StringBuilder("#" + seq + " " + an.getName() + "." + m + " n=" +
            set.getNumAddresses() + " ranges=" + set.getNumAddressRanges());
        for (Address w : watch) if (set.contains(w)) sb.append(" has:").append(w);
        if (set.getNumAddresses() <= 12) {
            sb.append(" set=");
            for (AddressRange r : set) sb.append(r).append(' ');
        }
        log(sb.toString());
    }

    void after(Analyzer an, String m) {
        if (currentProgram.getFunctionManager().getFunctionCount() != known.size()) {
            diff("#" + seq + " " + an.getName() + "." + m);
        }
        for (Address w : watch) {
            Function f = currentProgram.getFunctionManager().getFunctionContaining(w);
            Function at = currentProgram.getFunctionManager().getFunctionAt(w);
            Instruction in = currentProgram.getListing().getInstructionAt(w);
            String st = "  state " + w + " fn@=" + (at != null) + " in=" +
                (f == null ? "none" : f.getEntryPoint() + " body=" + f.getBody().getNumAddresses() +
                    "/" + f.getBody().getNumAddressRanges()) + " insn=" + (in != null);
            if (in != null && in.getFlowType().isJump()) {
                st += " flow=" + in.getFlowType().getName();
                for (Reference r : in.getReferencesFrom()) {
                    st += " ->" + r.getToAddress() + ":" + r.getReferenceType();
                }
            }
            if (!st.equals(last.put(w, st))) log("#" + seq + st);
        }
    }
}
