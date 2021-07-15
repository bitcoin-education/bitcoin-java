package bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class TaggedHash {
    public static byte[] hash(String tag, byte[] key) {
        byte[] shaTag = Sha256.hash(tag.getBytes(StandardCharsets.UTF_8));
        byte[] shaTags = ByteUtils.concatenate(shaTag, shaTag);
        return Sha256.hash(ByteUtils.concatenate(shaTags, key));
    }

    public static BigInteger hashToBigInteger(String tag, byte[] key) {
        return new BigInteger(1, hash(tag, key));
    }
}
