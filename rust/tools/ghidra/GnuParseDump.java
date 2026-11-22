// The oracle of `ghidra-rs gnu-parse`: what GnuDemangler.demangle makes of a mangled name once
// the native demangler answered, for a list of `mangled<TAB>native text` lines on stdin (the
// native text as demangler_gnu_v2_41 printed it). The native call is not made: the skip rules,
// the prefix handling, the trim and the failure checks of GnuDemangler.demangleInternal are
// copied below (it is private), then GnuDemanglerParser.parse(mangled, text, true) runs as
// GnuDemangler.parse calls it with the analyzer's options (demangleOnlyKnownPatterns false,
// standard replacements on). One line per input, tab separated, every value escaped
// (\\ \t \n \r), null as <null>:
//   mangled NONE (GnuDemangler returns null or throws a DemangledException) | ERR <exception
//   class> | OK, then for OK: kind name demangled-name original raw namespace(innermost first,
//   `getNamespaceName = getDemangledName` joined by ` | `) the namespace's getNamespaceString
//   signature (<ERR class> when getSignature throws) special-prefix flags(const virtual static thunk
//   volatile, 0/1) backup-plate-comment, then for a DemangledFunction: calling-convention
//   return-type parameters(joined by ` , `) template overloaded-operator; for a DemangledString:
//   string length.
// Application is initialised headlessly from the jars' layout (GhidraApplicationLayout finds
// the install from the class path), so the replacements file is found as in Ghidra. Its log
// lines go to stdout and start with "INFO ":
//   CP="$(find $G/Ghidra -name '*.jar' | tr '\n' :)"
//   javac -cp "$CP" -d <dir> GnuParseDump.java
//   java -cp "$CP<dir>" GnuParseDump < tsv | grep -v '^INFO '
import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.GnuDemanglerParser;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;

public class GnuParseDump {

	public static void main(String[] args) throws Exception {
		new GnuParseDump().launch(new GhidraApplicationLayout(), args);
	}

	private static final String DWARF_REF = "DW.ref.";
	private static final String GLOBAL_PREFIX = "_GLOBAL_";

	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
		BufferedReader in =
			new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
		PrintWriter out = new PrintWriter(new BufferedWriter(
			new OutputStreamWriter(System.out, StandardCharsets.UTF_8), 1 << 16));
		String line;
		while ((line = in.readLine()) != null) {
			int tab = line.indexOf('\t');
			String mangled = tab < 0 ? line : line.substring(0, tab);
			String text = tab < 0 ? "" : line.substring(tab + 1);
			StringBuilder b = new StringBuilder(esc(mangled));
			try {
				DemangledObject d = demangle(mangled, text);
				if (d == null) {
					b.append("\tNONE");
				}
				else {
					dump(b, d);
				}
			}
			catch (DemangledException e) {
				b.append("\tNONE");
			}
			catch (Throwable e) {
				b.append("\tERR ").append(e.getClass().getSimpleName());
			}
			out.println(b);
		}
		out.flush();
	}

	// GnuDemangler.demangleInternal with the native call replaced by `text`
	private static DemangledObject demangle(String mangled, String text)
			throws DemangledException {
		if (mangled.indexOf("@") > 0 || mangled.startsWith("___")) {
			return null;
		}
		String originalMangled = mangled;
		String globalPrefix = null;
		if (mangled.startsWith(GLOBAL_PREFIX)) {
			int index = mangled.indexOf("_Z");
			if (index > 0) {
				globalPrefix = mangled.substring(0, index);
				mangled = mangled.substring(index);
			}
		}
		else if (mangled.startsWith("__Z")) {
			mangled = mangled.substring(1);
		}
		else if (mangled.startsWith("._Z")) {
			mangled = mangled.substring(1);
		}
		boolean isDwarf = false;
		if (mangled.startsWith(DWARF_REF)) {
			mangled = mangled.substring(DWARF_REF.length());
			isDwarf = true;
		}
		String demangled = text.trim();
		if (demangled.length() == 0 || mangled.equals(demangled)) {
			throw new DemangledException(true);
		}
		DemangledObject d = new GnuDemanglerParser().parse(originalMangled, demangled, true);
		if (d == null) {
			return null;
		}
		if (globalPrefix != null) {
			String prefix = switch (globalPrefix) {
				case "_GLOBAL__sub_I_" -> "global_init_constructor_";
				case "_GLOBAL__sub_D_" -> "global_destructor_";
				default -> globalPrefix;
			};
			DemangledFunction f =
				new DemangledFunction(originalMangled, demangled, prefix + d.getName());
			f.setNamespace(d.getNamespace());
			d = f;
		}
		if (isDwarf) {
			DemangledAddressTable dat =
				new DemangledAddressTable(originalMangled, demangled, (String) null, false);
			dat.setSpecialPrefix("DWARF Debug ");
			dat.setName(d.getName());
			dat.setNamespace(d.getNamespace());
			return dat;
		}
		return d;
	}

	private static void dump(StringBuilder b, DemangledObject d) throws Exception {
		b.append("\tOK");
		col(b, d.getClass().getSimpleName());
		col(b, d.getName());
		col(b, d.getDemangledName());
		col(b, d.getOriginalDemangled());
		col(b, d.getRawDemangled());
		StringBuilder ns = new StringBuilder();
		for (Demangled n = d.getNamespace(); n != null; n = n.getNamespace()) {
			if (ns.length() > 0) {
				ns.append(" | ");
			}
			ns.append(n.getNamespaceName()).append(" = ").append(n.getDemangledName());
		}
		col(b, ns.toString());
		col(b, d.getNamespace() == null ? null : d.getNamespace().getNamespaceString());
		String sig;
		try {
			sig = d.getSignature(false);
		}
		catch (RuntimeException e) {
			sig = "<ERR " + e.getClass().getSimpleName() + ">";
		}
		col(b, sig);
		col(b, d.getSpecialPrefix());
		col(b, bit(d.isConst()) + bit(d.isVirtual()) + bit(d.isStatic()) + bit(d.isThunk()) +
			bit(d.isVolatile()));
		col(b, (String) field(DemangledObject.class, d, "plateComment"));
		if (d instanceof DemangledFunction f) {
			col(b, f.getCallingConvention());
			col(b, f.getReturnType() == null ? null : f.getReturnType().getSignature());
			StringBuilder ps = new StringBuilder();
			for (DemangledParameter p : f.getParameters()) {
				if (ps.length() > 0) {
					ps.append(" , ");
				}
				ps.append(p.getType().getSignature());
			}
			col(b, ps.toString());
			col(b, f.getTemplate() == null ? null : f.getTemplate().toTemplate());
			col(b, bit((Boolean) field(DemangledFunction.class, f, "isOverloadedOperator")));
		}
		else if (d instanceof DemangledString s) {
			col(b, s.getString());
			col(b, Integer.toString(s.getLength()));
		}
	}

	private static Object field(Class<?> c, Object o, String name) throws Exception {
		Field f = c.getDeclaredField(name);
		f.setAccessible(true);
		return f.get(o);
	}

	private static String bit(boolean b) {
		return b ? "1" : "0";
	}

	private static void col(StringBuilder b, String s) {
		b.append('\t').append(s == null ? "<null>" : esc(s));
	}

	private static String esc(String s) {
		return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r",
			"\\r");
	}
}
