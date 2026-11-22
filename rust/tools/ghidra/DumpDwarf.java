// Post-script (run with -noanalysis): the DWARF import alone, as DWARFAnalyzer.added does it with
// the default options, then one line per data type under /DWARF and one line per function whose
// signature the import set (signature source IMPORTED), in the form of `ghidra-rs dwarf`.
// Arguments: output path.
//@category GhidraRs
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf.DWARFImporter;
import ghidra.app.util.bin.format.dwarf.DWARFProgram;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import java.io.PrintWriter;
import java.util.*;

public class DumpDwarf extends GhidraScript {
    static String ref(DataType dt) {
        return dt == null ? "null" : dt.getPathName();
    }

    static String body(DataType dt) {
        StringBuilder sb = new StringBuilder();
        if (dt instanceof Structure || dt instanceof Union) {
            Composite c = (Composite) dt;
            sb.append(dt instanceof Union ? "union" : "struct").append(" len=").append(c.getLength())
                .append(c.isPackingEnabled() ? " packed align=" + c.getAlignment() : "");
            for (DataTypeComponent dtc : c.getDefinedComponents()) {
                sb.append(" | ").append(dtc.getOffset()).append(':').append(dtc.getLength())
                    .append(':').append(dtc.getFieldName()).append(':');
                if (dtc.getDataType() instanceof BitFieldDataType bf) {
                    sb.append(ref(bf.getBaseDataType())).append(":bf").append(bf.getBitOffset())
                        .append(',').append(bf.getBitSize());
                } else {
                    sb.append(ref(dtc.getDataType()));
                }
            }
        } else if (dt instanceof TypeDef td) {
            sb.append("typedef -> ").append(ref(td.getDataType()));
        } else if (dt instanceof Enum e) {
            sb.append("enum len=").append(e.getLength()).append(" vals=");
            List<String> names = new ArrayList<>(Arrays.asList(e.getNames()));
            names.sort(Comparator.comparingLong((String n) -> e.getValue(n)).thenComparing(n -> n));
            StringJoiner j = new StringJoiner(",");
            for (String n : names) j.add(n + "=" + e.getValue(n));
            sb.append(j);
        } else if (dt instanceof FunctionDefinition f) {
            sb.append("funcdef ").append(sig(f.getCallingConventionName(), f.getReturnType(),
                f.hasVarArgs(), f.hasNoReturn()));
            for (ParameterDefinition p : f.getArguments())
                sb.append(" | ").append(p.getName()).append(':').append(ref(p.getDataType()));
        } else if (dt instanceof Pointer || dt instanceof Array) {
            return null;
        } else {
            sb.append("other ").append(dt.getClass().getSimpleName()).append(" len=").append(dt.getLength());
        }
        return sb.toString();
    }

    static String sig(String cc, DataType ret, boolean varargs, boolean noreturn) {
        return "cc=" + cc + " ret=" + ref(ret) + (varargs ? " varargs" : "") + (noreturn ? " noreturn" : "");
    }

    @Override
    public void run() throws Exception {
        DWARFImportOptions opts = new DWARFImportOptions();
        DWARFSectionProvider dsp = DWARFSectionProviderFactory.createSectionProviderFor(currentProgram, monitor);
        try (DWARFProgram prog = new DWARFProgram(currentProgram, opts, dsp)) {
            prog.init(monitor);
            new DWARFImporter(prog, monitor).performImport().logSummaryResults();
        }
        List<String> lines = new ArrayList<>();
        Iterator<DataType> it = currentProgram.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (!dt.getCategoryPath().getPath().startsWith("/DWARF")) continue;
            String b = body(dt);
            if (b != null) lines.add("T " + dt.getPathName() + "\t" + b);
        }
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.getSignatureSource() != SourceType.IMPORTED) continue;
            StringBuilder sb = new StringBuilder("F " + f.getEntryPoint() + "\t" + f.getName(true) + " "
                + sig(f.getCallingConventionName(), f.getReturnType(), f.hasVarArgs(), f.hasNoReturn()));
            for (Parameter p : f.getParameters())
                sb.append(" | ").append(p.getName()).append(':').append(ref(p.getDataType()));
            lines.add(sb.toString());
        }
        Collections.sort(lines);
        try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
            for (String l : lines) out.println(l);
        }
    }
}
