// Runs a cases file through Bouncy Castle's lightweight ML-DSA verifier (ML-DSA-87, pure).
// usage: java -cp BCPROV.jar BcVerify.java CASES.tsv BCPROV_VERSION
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does.
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.MLDSASigner;

public class BcVerify {
  static byte[] unhex(String s) {
    if (s.equals("-")) return new byte[0];
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
    int n = 0; List<String> wrong = new ArrayList<>();
    for (String line : Files.readAllLines(Paths.get(a[0]))) {
      String[] p = line.split("\t");
      boolean got = verify(unhex(p[1]), unhex(p[2]), unhex(p[3]), unhex(p[4]));
      n++;
      if (got != p[5].equals("1")) wrong.add(p[0]);
    }
    System.out.println("Bouncy Castle bcprov-jdk18on " + a[1] + " (Java " + System.getProperty("java.version") + "): " + n + " cases, " + wrong.size() + " disagree with the expected result " + wrong);
    System.exit(wrong.isEmpty() ? 0 : 1);
  }
}
