package bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static java.math.BigInteger.valueOf;

public class ExtendedKey {
    public static final String MAINNET_PUBLIC_PREFIX = "0488B21E";
    public static final String MAINNET_PRIVATE_PREFIX = "0488ADE4";
    public static final String TESTNET_PUBLIC_PREFIX = "043587CF";
    public static final String TESTNET_PRIVATE_PREFIX = "04358394";

    private final byte[] key;

    private final String prefix;

    private final String fingerprint;

    private final String depth;

    private final String childNumber;

    public ExtendedKey(byte[] key, String prefix, String depth, String fingerprint, String childNumber) {
        this.key = key;
        this.prefix = prefix;
        this.depth = depth;
        this.fingerprint = fingerprint;
        this.childNumber = childNumber;
    }

    public static ExtendedKey from(byte[] key, boolean isPrivate, String environment, long depth, String fingerprint, long childNumber) {
        String prefix;
        if (isPrivate && environment.equals("mainnet")) {
            prefix = MAINNET_PRIVATE_PREFIX;
        } else if (isPrivate && environment.equals("testnet")) {
            prefix = TESTNET_PRIVATE_PREFIX;
        } else if (environment.equals("mainnet")) {
            prefix = MAINNET_PUBLIC_PREFIX;
        } else if (environment.equals("testnet")) {
            prefix = TESTNET_PUBLIC_PREFIX;
        } else {
            throw new IllegalArgumentException("Invalid environment, must be testnet or mainnet");
        }

        return new ExtendedKey(
            key,
            prefix,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(1, valueOf(depth))),
            fingerprint,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(4, valueOf(childNumber)))
        );
    }

    public String serialize() throws NoSuchAlgorithmException {
        byte[] chainCode = ByteUtils.subArray(key, 32, key.length);
        byte[] privateKey = ByteUtils.subArray(key, 0, 32);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decode(prefix));
        byteArrayOutputStream.writeBytes(Hex.decode(depth));
        byteArrayOutputStream.writeBytes(Hex.decode(fingerprint));
        byteArrayOutputStream.writeBytes(Hex.decode(childNumber));
        byteArrayOutputStream.writeBytes(chainCode);
        byteArrayOutputStream.writeBytes(Hex.decode("00"));
        byteArrayOutputStream.writeBytes(privateKey);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public byte[] getKey() {
        return key;
    }
}
