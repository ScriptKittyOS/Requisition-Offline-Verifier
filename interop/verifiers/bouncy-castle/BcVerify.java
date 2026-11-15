// Runs a cases file through Bouncy Castle's lightweight ML-DSA verifier (ML-DSA-87, pure).
// usage: java -cp BCPROV.jar BcVerify.java CASES.tsv
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.MLDSASigner;

public class BcVerify {
  static byte[] unhex(String s) {
    if (s.equals("-")) return new byte[0];
    if (s.isEmpty() || s.length() % 2 != 0 || !s.matches("[0-9a-fA-F]*")) { System.err.println("bad hex"); System.exit(2); }
    byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    return b;
  }
  static boolean verify(byte[] pk, byte[] sig, byte[] msg, byte[] ctx) {
    try {
      MLDSAPublicKeyParameters key = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, pk);
      MLDSASigner s = new MLDSASigner();
      s.init(false, new ParametersWithContext(key, ctx));
      s.update(msg, 0, msg.length);
      return s.verifySignature(sig);
    } catch (RuntimeException e) {
      return false;
    }
  }
  public static void main(String[] a) throws Exception {
    if (a.length != 1) { System.err.println("usage: BcVerify.java CASES.tsv"); System.exit(2); }
    List<String> lines = null;
    try { lines = Arrays.asList(new String(Files.readAllBytes(Paths.get(a[0])), java.nio.charset.StandardCharsets.UTF_8).split("\n", -1)); } catch (Exception e) { System.err.println("cannot read " + a[0]); System.exit(2); }
    int n = 0; List<String> wrong = new ArrayList<>();
    for (String line : lines) {
      if (line.isEmpty()) continue;
      if (line.endsWith("\r")) line = line.substring(0, line.length() - 1);
      String[] p = line.split("\t", -1);
      if (p.length != 6) { System.err.println("bad line"); System.exit(2); }
      if (!p[5].equals("0") && !p[5].equals("1")) { System.err.println("bad expected result in case " + p[0]); System.exit(2); }
      boolean got = verify(unhex(p[1]), unhex(p[2]), unhex(p[3]), unhex(p[4]));
      n++;
      if (got != p[5].equals("1")) wrong.add(p[0]);
    }
    if (n == 0) { System.err.println("no cases"); System.exit(2); }
    System.out.println("Bouncy Castle bcprov-jdk18on " + new org.bouncycastle.jce.provider.BouncyCastleProvider().getVersionStr() + " (Java " + System.getProperty("java.version") + "): " + n + " cases, " + wrong.size() + " disagree with the expected result " + wrong);
    System.exit(wrong.isEmpty() ? 0 : 1);
  }
}
