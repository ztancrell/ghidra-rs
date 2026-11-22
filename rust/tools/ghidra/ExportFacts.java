// The facts of a Ghidra program for ghidra-rs (`load facts`): the answers Java Ghidra gives its
// decompiler, recorded once. Each answer is the XML that DecompileCallback sends (the same
// calls DecompInterface makes), so nothing of the encoding is redone here.
// Argument: the output file. One record per line, fields separated by tabs, addresses in hex:
//   ghidra-rs-facts 2
//   coretypes <xml>                  PcodeDataTypeManager.encodeCoreTypes
//   block <first> <last> <r|w>[v]    a memory block: writable or not, volatile
//   wref <addr>                      an address of a non-writable block with a write reference
//   func <entry> <xml>               getMappedSymbols(entry) while that function is decompiled
//   body <entry> <first>-<last> ...  the ranges of the function's body
//   tracked <entry> <xml>            getTrackedRegisters(entry), written when the registers differ
//                                    from those of the function before (they hold until the next)
//   comments <entry> <xml>           getComments(entry, every type), when there is one
//   data <first> <length> <xml>      getMappedSymbols(first) for defined or labelled data
//   extref <addr> <xml>              getExternalRef(addr) for a pointer to an external location
//   depth <entry> <to> <change>      a stack-depth-change override at a call site of the function
//                                    (what getExtraPopOverride reads): the flow target and the value
//   string <first> <length> <n|->    defined string data (StringDataInstance): n when getStringData
//                                    reads n plain ASCII characters, the first n bytes of the data,
//                                    and the rest of the data is zero; - for any other string
//   undef <first> <last> <prefix>    undefined bytes of a block that is not writable: Java sends a
//                                    read-only 1-byte symbol <prefix><address> of type undefined for
//                                    each without a record of its own (encodeData)
//   label <addr> <name> [<entry>]    getCodeLabel(addr) for a primary symbol at an instruction; with
//                                    <entry> the name holds only while that function is decompiled
//                                    (a label of its namespace has another name elsewhere)
//   override <addr> <kind>           an instruction with a flow, fall-through or length override
//   type <id> <xml>                  getDataType for each <typeref> of the records above
//   ns <id> <xml>                    getNamespacePath for each namespace id of the records above
// Newlines and tabs inside the XML are written as character references.
// `ghidra-rs analyze --facts` (factsout.rs) writes the same file from its own analysis, with one
// more record for what it does not derive: underived <address> <function|comments|label>.
//@category ghidra-rs
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.decompiler.DecompileCallback;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;

public class ExportFacts extends GhidraScript {
    private static final Pattern TYPEREF = Pattern.compile("<typeref name=\"([^\"]*)\" id=\"(0x[0-9a-f]+)\"");
    private static final Pattern SCOPE = Pattern.compile("<(?:doc|parent) id=\"(0x[0-9a-f]+)\"");
    private BufferedWriter out;
    private final HashSet<String> typeIds = new HashSet<>();
    private final ArrayDeque<String[]> typeQueue = new ArrayDeque<>();
    private final HashSet<String> scopeIds = new HashSet<>();
    private String lastTracked = "";

    private static String hex(Address a) {
        return Long.toHexString(a.getOffset());
    }

    private static String unescape(String s) {
        return s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")
            .replace("&amp;", "&");
    }

    // one record; the XML is scanned for the types and namespaces it refers to
    private void record(String head, String xml) throws Exception {
        Matcher m = TYPEREF.matcher(xml);
        while (m.find()) {
            if (typeIds.add(m.group(2))) {
                typeQueue.add(new String[] { unescape(m.group(1)), m.group(2) });
            }
        }
        m = SCOPE.matcher(xml);
        while (m.find()) {
            scopeIds.add(m.group(1));
        }
        out.write(head);
        out.write('\t');
        out.write(xml.replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#9;"));
        out.write('\n');
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        PcodeDataTypeManager dtmanage = new PcodeDataTypeManager(currentProgram, new IdentityNameTransformer());
        DecompileCallback cb = new DecompileCallback(currentProgram, currentProgram.getLanguage(),
            currentProgram.getCompilerSpec(), dtmanage);
        out = Files.newBufferedWriter(new File(getScriptArgs()[0]).toPath(), StandardCharsets.UTF_8);
        out.write("ghidra-rs-facts 2\n");

        XmlEncode enc = new XmlEncode(false);
        dtmanage.encodeCoreTypes(enc);
        String core = enc.toString();
        Matcher cm = Pattern.compile(" id=\"(0x[0-9a-f]+)\"").matcher(core);
        while (cm.find()) {
            typeIds.add(cm.group(1));
        }
        record("coretypes", core);

        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            // the decompiler reads the default space only: a block of another space (ELF's
            // non-loaded sections, `.comment` and `.debug_*`, in OTHER) has no record, as its
            // offsets would collide with ram's
            if (!ram(b.getStart())) {
                continue;
            }
            out.write("block\t" + hex(b.getStart()) + "\t" + hex(b.getEnd()) + "\t" + (b.isWrite() ? "w" : "r") +
                (b.isVolatile() ? "v" : "") + "\n");
            if (b.isWrite()) {
                continue;
            }
            // MappedEntry.getMutabilityOfAddress: a write among the first 100 references
            AddressIterator dests = currentProgram.getReferenceManager()
                .getReferenceDestinationIterator(new AddressSet(b.getStart(), b.getEnd()), true);
            while (dests.hasNext()) {
                Address a = dests.next();
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(a);
                for (int count = 0; refs.hasNext() && count < 100; count++) {
                    if (refs.next().getReferenceType().isWrite()) {
                        out.write("wref\t" + hex(a) + "\n");
                        break;
                    }
                }
            }
            if (!b.isVolatile()) {
                undefined(cb, b);
            }
        }

        for (Function f : listing.getFunctions(true)) {
            monitor.checkCancelled();
            Address entry = f.getEntryPoint();
            cb.setFunction(f, entry, null);
            enc = new XmlEncode(false);
            cb.getMappedSymbols(entry, enc);
            record("func\t" + hex(entry), enc.toString());
            StringBuilder body = new StringBuilder("body\t" + hex(entry));
            for (AddressRange r : f.getBody()) {
                body.append('\t').append(hex(r.getMinAddress())).append('-').append(hex(r.getMaxAddress()));
            }
            out.write(body.append('\n').toString());
            // DecompileCallback.getExtraPopOverride: the overrides in this function's body
            AddressIterator changes = CallDepthChangeInfo.getStackDepthChanges(currentProgram, f.getBody());
            while (changes.hasNext()) {
                Address at = changes.next();
                Integer change = CallDepthChangeInfo.getStackDepthChange(currentProgram, at);
                for (Reference ref : currentProgram.getReferenceManager().getFlowReferencesFrom(at)) {
                    if (change != null) {
                        Address to = ref.getToAddress();
                        out.write("depth\t" + hex(entry) + "\t" + (to.isMemoryAddress() ? hex(to) : "-") + "\t" + change + "\n");
                    }
                }
            }
            enc = new XmlEncode(false);
            cb.getTrackedRegisters(entry, enc);
            String sets = enc.toString().replaceFirst(" offset=\"0x[0-9a-f]+\"", "");
            if (!sets.equals(lastTracked)) {
                record("tracked\t" + hex(entry), enc.toString());
                lastTracked = sets;
            }
            enc = new XmlEncode(false);
            cb.getComments(entry, 15, enc);
            if (enc.toString().contains("<comment ")) {
                record("comments\t" + hex(entry), enc.toString());
            }
        }
        // no function is being decompiled: an address without one
        cb.setFunction(null, currentProgram.getMinAddress(), null);

        // data: everything defined, and everything a primary symbol labels
        HashSet<Address> seen = new HashSet<>();
        for (Data d : listing.getDefinedData(true)) {
            monitor.checkCancelled();
            if (!ram(d.getMinAddress())) {
                continue; // as the blocks above
            }
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            if (sdi != StringDataInstance.NULL_INSTANCE) {
                out.write("string\t" + hex(d.getMinAddress()) + "\t" + d.getLength() + "\t" + plain(d, sdi) + "\n");
            }
            data(cb, d, seen);
        }
        for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
            monitor.checkCancelled();
            Address a = s.getAddress();
            if (!s.isPrimary() || !a.isMemoryAddress() || !ram(a)) {
                continue;
            }
            if (listing.getInstructionAt(a) != null) {
                // a block can start at any instruction: in a body, at an entry or outside every function
                String name = cb.getCodeLabel(a);
                String own = "";
                if (s.getParentNamespace() instanceof Function fn) {
                    // getNamespacePrefix: no prefix while the label's own function is decompiled
                    cb.setFunction(fn, fn.getEntryPoint(), null);
                    String inside = cb.getCodeLabel(a);
                    cb.setFunction(null, currentProgram.getMinAddress(), null);
                    if (!inside.equals(name)) {
                        name = inside;
                        own = "\t" + hex(fn.getEntryPoint());
                    }
                }
                if (name != null) {
                    out.write("label\t" + hex(a) + "\t" + name + own + "\n");
                }
            }
            if (listing.getFunctionAt(a) != null || listing.getFunctionContaining(a) != null) {
                continue;
            }
            Data d = listing.getDataContaining(a);
            if (d != null) {
                data(cb, d, seen);
            }
            else if (s.isGlobal() && seen.add(a)) {
                enc = new XmlEncode(false);
                cb.getMappedSymbols(a, enc);
                record("data\t" + hex(a) + "\t1", enc.toString());
            }
        }

        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (ins.getFlowOverride() != FlowOverride.NONE) {
                out.write("override\t" + hex(ins.getAddress()) + "\t" + ins.getFlowOverride() + "\n");
            }
            if (ins.isFallThroughOverridden()) {
                out.write("override\t" + hex(ins.getAddress()) + "\tFALLTHROUGH\n");
            }
            if (ins.isLengthOverridden()) {
                out.write("override\t" + hex(ins.getAddress()) + "\tLENGTH\n");
            }
        }

        while (!typeQueue.isEmpty()) {
            String[] t = typeQueue.remove();
            enc = new XmlEncode(false);
            cb.getDataType(t[0], Long.parseUnsignedLong(t[1].substring(2), 16), enc);
            record("type\t" + t[1].substring(2), enc.toString());
        }
        for (String id : scopeIds.toArray(new String[0])) {
            if (Long.parseUnsignedLong(id.substring(2), 16) != 0) {
                enc = new XmlEncode(false);
                cb.getNamespacePath(Long.parseUnsignedLong(id.substring(2), 16), enc);
                record("ns\t" + id.substring(2), enc.toString());
            }
        }
        out.close();
    }

    private void data(DecompileCallback cb, Data d, HashSet<Address> seen) throws Exception {
        Address a = d.getMinAddress();
        boolean ext = d.isPointer() && d.getPrimaryReference(0) instanceof ExternalReference;
        // lookupSymbol: the function containing an address comes before its data
        if (!seen.add(a) || (!ext && currentProgram.getListing().getFunctionContaining(a) != null)) {
            return;
        }
        XmlEncode enc = new XmlEncode(false);
        cb.getMappedSymbols(a, enc);
        if (enc.toString().startsWith("<hole")) {
            return;
        }
        record("data\t" + hex(a) + "\t" + d.getLength(), enc.toString());
        if (ext) {
            enc = new XmlEncode(false);
            cb.getExternalRef(a, enc);
            record("extref\t" + hex(a), enc.toString());
        }
    }

    // The undefined bytes of a block that is not writable. DecompileCallback.encodeData gives each
    // one without a primary symbol (so without a reference: its mutability is the block's) a
    // read-only symbol of one byte, named by SymbolUtilities.getDynamicName. One record per range;
    // ghidra-rs writes the symbol's XML itself (decomp/facts.rs, `undef_symbol`), so the first such
    // byte of each range is checked here against the same text.
    // the default address space, the one the decompiler reads
    private boolean ram(Address a) {
        return a.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace());
    }

    private void undefined(DecompileCallback cb, MemoryBlock b) throws Exception {
        Listing listing = currentProgram.getListing();
        AddressSetView ranges =
            listing.getUndefinedRanges(new AddressSet(b.getStart(), b.getEnd()), false, monitor);
        for (AddressRange r : ranges) {
            monitor.checkCancelled();
            Address s = r.getMinAddress();
            while (s != null && r.contains(s) && (currentProgram.getSymbolTable().getPrimarySymbol(s) != null ||
                listing.getFunctionContaining(s) != null)) {
                s = s.next();
            }
            if (s == null || !r.contains(s)) {
                continue; // every byte has a record of its own or lies in a function
            }
            String name = SymbolUtilities.getDynamicName(currentProgram, s);
            String tail = String.format("%08x", s.getOffset());
            if (name == null || !name.endsWith(tail)) {
                throw new RuntimeException("undefined byte at " + s + ": the name " + name);
            }
            String prefix = name.substring(0, name.length() - tail.length());
            String expect = "<doc id=\"0x0\"><mapsym><symbol id=\"0x0\" name=\"" + prefix + tail +
                "\" typelock=\"true\" namelock=\"true\" readonly=\"true\" merge=\"false\" cat=\"-1\">" +
                "<typeref name=\"undefined\" id=\"0xc000000000000000\"/></symbol><addr space=\"ram\" offset=\"0x" +
                hex(s) + "\" size=\"1\"/><rangelist/></mapsym></doc>";
            XmlEncode enc = new XmlEncode(false);
            cb.getMappedSymbols(s, enc);
            if (!enc.toString().equals(expect)) {
                throw new RuntimeException("undefined byte at " + s + ": " + enc);
            }
            out.write("undef\t" + hex(r.getMinAddress()) + "\t" + hex(r.getMaxAddress()) + "\t" + prefix + "\n");
        }
    }

    // What DecompileCallback.getStringData reads from defined string data, when a read of the raw
    // bytes up to a zero gives the same: the number of characters, all plain ASCII of one byte,
    // the same as the first bytes of the data (so one byte each), with only zeros after them in the
    // data. "-" for
    // any other string (a translation shown, wide or other characters, a length prefix).
    private String plain(Data d, StringDataInstance sdi) {
        try {
            if (sdi.isShowTranslation() && sdi.getTranslatedValue() != null) {
                return "-";
            }
            String v = sdi.getStringValue();
            byte[] bytes = d.getBytes();
            if (v == null || v.length() > bytes.length) {
                return "-";
            }
            for (int i = 0; i < bytes.length; i++) {
                char c = i < v.length() ? v.charAt(i) : 0;
                boolean ok = i >= v.length() || (c >= 0x20 && c <= 0x7e) || c == 9 || c == 10 || c == 13;
                if (!ok || bytes[i] != (byte) c) {
                    return "-";
                }
            }
            return Integer.toString(v.length());
        }
        catch (Exception e) {
            return "-";
        }
    }
}
