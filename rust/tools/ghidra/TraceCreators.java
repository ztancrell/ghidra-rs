// Pre-script: logs which auto-analysis analyzer made or removed each function. Every analyzer's
// added()/removed() call is wrapped; the program's FUNCTION_ADDED/FUNCTION_REMOVED events are
// flushed before and after each call, so an event delivered inside a call belongs to that
// analyzer and one delivered before a call was made between calls (by queued commands such as
// CreateFunctionCmd), after the analyzer named. Cheaper than TraceFunctions.java, which diffs
// the whole function set around every call.
// Output lines: "+ <entry> <analyzer>" or "- <entry> <analyzer>", where <analyzer> is
// "in:<name>" or "after:<name>".
// Arguments: output log path.
//@category Mercs2
import ghidra.app.plugin.core.analysis.AnalysisScheduler;
import ghidra.app.plugin.core.analysis.AnalysisTaskList;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;

public class TraceCreators extends GhidraScript {
    static ghidra.framework.model.DomainObjectListener listener;
    PrintWriter out;
    volatile String where = "after:import";

    @Override
    @SuppressWarnings("unchecked")
    public void run() throws Exception {
        out = new PrintWriter(new java.io.FileWriter(getScriptArgs()[0]), true);
        // the program holds its listeners weakly: keep this one alive past the script
        listener = (DomainObjectChangedEvent ev) -> {
            for (DomainObjectChangeRecord r : ev) {
                String sign = r.getEventType() == ProgramEvent.FUNCTION_ADDED ? "+ "
                    : r.getEventType() == ProgramEvent.FUNCTION_REMOVED ? "- " : null;
                if (sign != null && r instanceof ProgramChangeRecord p) {
                    out.println(sign + p.getStart() + " " + where);
                }
            }
        };
        currentProgram.addListener(listener);
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
                        if (trace) {
                            currentProgram.flushEvents();
                            where = "in:" + real.getName();
                        }
                        try {
                            return m.invoke(real, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        } finally {
                            if (trace) {
                                currentProgram.flushEvents();
                                where = "after:" + real.getName();
                            }
                        }
                    }));
                wrapped++;
            }
        }
        out.println("wrapped " + wrapped + " analyzers");
    }
}
