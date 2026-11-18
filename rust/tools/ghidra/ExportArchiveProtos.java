// The function prototypes of a Ghidra data-type archive for `ghidra-rs analyze --facts --protos`:
// what Java Ghidra's "Apply Data Archives" analyzer gives the imports of a program, exported once
// per archive (not per program), so the facts of a program need no Java Ghidra project.
// Each function definition of the archive is applied to an external function of the current
// program as the analyzer does (ApplyFunctionSignatureCmd, source IMPORTED), and the answer of
// DecompileCallback.getExternalRef for a pointer to it is written with `@ADDR@` and `@SIZE@`
// where the pointer's address and the function symbol's size stand.
// The current program only lends its language and compiler spec (tools/ghidra-protos.sh imports
// a scratch file as x86:LE:32:default:windows); nothing of it is read.
// Arguments: the output file, then the archive's name (default windows_vs12_32).
//   ghidra-rs-protos 1
//   proto <name> <xml>
//   type <id> <xml>       getDataType for each <typeref> of the records above
//@category ghidra-rs
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompileCallback;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class ExportArchiveProtos extends GhidraScript {
    private static final Pattern TYPEREF = Pattern.compile("<typeref name=\"([^\"]*)\" id=\"(0x[0-9a-f]+)\"");

    private static String unescape(String s) {
        return s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")
            .replace("&amp;", "&");
    }

    private static String line(String xml) {
        return xml.replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#9;");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String archive = args.length > 1 ? args[1] : "windows_vs12_32";
        ResourceFile file = DataTypeArchiveUtility.findArchiveFile(archive);
        if (file == null) {
            throw new RuntimeException("no data-type archive " + archive);
        }
        FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(file, false);
        PcodeDataTypeManager dtmanage = new PcodeDataTypeManager(currentProgram, new IdentityNameTransformer());
        DecompileCallback cb = new DecompileCallback(currentProgram, currentProgram.getLanguage(),
            currentProgram.getCompilerSpec(), dtmanage);
        // the pointer every function is asked through
        Address slot = currentProgram.getMinAddress();
        clearListing(slot, slot.add(3));
        createData(slot, PointerDataType.dataType);
        cb.setFunction(null, slot, null);
        String at = "space=\"ram\" offset=\"0x" + Long.toHexString(slot.getOffset()) + "\"";
        if (slot.getOffset() == 0) {
            at = "space=\"ram\" offset=\"0x0\"";
        }

        HashSet<String> typeIds = new HashSet<>();
        ArrayDeque<String[]> typeQueue = new ArrayDeque<>();
        HashSet<String> names = new HashSet<>();
        int count = 0;
        try (BufferedWriter out =
            Files.newBufferedWriter(new File(args[0]).toPath(), StandardCharsets.UTF_8)) {
            out.write("ghidra-rs-protos 1\n");
            Iterator<FunctionDefinition> defs = dtm.getAllFunctionDefinitions();
            while (defs.hasNext()) {
                monitor.checkCancelled();
                FunctionDefinition def = defs.next();
                String name = def.getName();
                // the analyzer applies nothing where the archive has several definitions of a name
                if (name.contains("\t") || !names.add(name)) {
                    continue;
                }
                ExternalLocation loc;
                try {
                    loc = currentProgram.getExternalManager().addExtFunction("ARCHIVE", name, null,
                        SourceType.IMPORTED);
                }
                catch (Exception e) {
                    println("skipped " + name + ": " + e.getMessage());
                    continue;
                }
                Function f = loc.getFunction();
                new ApplyFunctionSignatureCmd(f.getEntryPoint(), def, SourceType.IMPORTED).applyTo(currentProgram);
                for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(slot)) {
                    currentProgram.getReferenceManager().delete(r);
                }
                currentProgram.getReferenceManager().addExternalReference(slot, "ARCHIVE", name, null,
                    SourceType.IMPORTED, 0, RefType.DATA);
                XmlEncode enc = new XmlEncode(false);
                cb.getExternalRef(slot, enc);
                String xml = enc.toString();
                String tail = "<addr " + at + " size=\"2\"/><rangelist/></mapsym></doc>";
                Matcher head = Pattern.compile("^(<doc id=\"0x0\"><mapsym><function id=\"0x[0-9a-f]+\" name=\"[^\"]*\") size=\"2\"")
                    .matcher(xml);
                if (!head.find() || !xml.endsWith(tail) || !xml.contains("<addr " + at + "/>")) {
                    println("skipped " + name + ": " + xml.substring(0, Math.min(200, xml.length())));
                    continue;
                }
                xml = head.group(1) + " size=\"@SIZE@\"" + xml.substring(head.end(), xml.length() - tail.length()) +
                    "<addr space=\"ram\" offset=\"@ADDR@\" size=\"@SIZE@\"/><rangelist/></mapsym></doc>";
                xml = xml.replace("<addr " + at + "/>", "<addr space=\"ram\" offset=\"@ADDR@\"/>");
                Matcher m = TYPEREF.matcher(xml);
                while (m.find()) {
                    if (typeIds.add(m.group(2))) {
                        typeQueue.add(new String[] { unescape(m.group(1)), m.group(2) });
                    }
                }
                out.write("proto\t" + name + "\t" + line(xml) + "\n");
                count++;
            }
            while (!typeQueue.isEmpty()) {
                String[] t = typeQueue.remove();
                XmlEncode enc = new XmlEncode(false);
                cb.getDataType(t[0], Long.parseUnsignedLong(t[1].substring(2), 16), enc);
                String xml = enc.toString();
                Matcher m = TYPEREF.matcher(xml);
                while (m.find()) {
                    if (typeIds.add(m.group(2))) {
                        typeQueue.add(new String[] { unescape(m.group(1)), m.group(2) });
                    }
                }
                out.write("type\t" + t[1].substring(2) + "\t" + line(xml) + "\n");
            }
        }
        dtm.close();
        println("exported " + count + " prototypes of " + archive);
    }
}
