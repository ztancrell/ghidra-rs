// Prints the UTF-16 units Java's Character.isLetter(char) accepts, as inclusive ranges, for
// rust/ghidra-rs/src/decomp/isletter.rs (the table of IllegalCharCppTransformer's letters).
//   java rust/tools/ghidra/IsLetterRanges.java > ranges.txt
public class IsLetterRanges {
    public static void main(String[] args) {
        int start = -1, n = 0;
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c <= 0x10000; c++) {
            boolean l = c < 0x10000 && Character.isLetter((char) c);
            if (l && start < 0) start = c;
            if (!l && start >= 0) {
                sb.append(String.format("(0x%04x, 0x%04x),", start, c - 1));
                sb.append(++n % 6 == 0 ? "\n" : " ");
                start = -1;
            }
        }
        System.out.print(sb.toString().trim() + "\n");
        System.err.println(n + " ranges, Java " + Runtime.version() + ", Unicode per Character");
    }
}
