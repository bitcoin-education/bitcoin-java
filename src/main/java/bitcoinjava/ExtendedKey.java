package bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static java.math.BigInteger.ONE;
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

    private final boolean isPrivate;

    private ExtendedKey(byte[] key, String prefix, String depth, String fingerprint, String childNumber, boolean isPrivate) {
        this.key = key;
        this.prefix = prefix;
        this.depth = depth;
        this.fingerprint = fingerprint;
        this.childNumber = childNumber;
        this.isPrivate = isPrivate;
    }

    public static ExtendedKey from(byte[] key, boolean isPrivate, String environment, long depth, String fingerprint, BigInteger childNumber) {
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
            Hex.toHexString(BigIntegers.asUnsignedByteArray(4, childNumber)),
            isPrivate
        );
    }

    public String serialize() throws NoSuchAlgorithmException {
        byte[] chainCode = ByteUtils.subArray(key, 32, key.length);
        byte[] keyBytes = ByteUtils.subArray(key, 0, 32);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decode(prefix));
        byteArrayOutputStream.writeBytes(Hex.decode(depth));
        byteArrayOutputStream.writeBytes(Hex.decode(fingerprint));
        byteArrayOutputStream.writeBytes(Hex.decode(childNumber));
        byteArrayOutputStream.writeBytes(chainCode);
        if (isPrivate) {
            byteArrayOutputStream.writeBytes(Hex.decode("00"));
            byteArrayOutputStream.writeBytes(keyBytes);
        } else {
            PrivateKey privateKey = new PrivateKey(new BigInteger(1, keyBytes));
            byteArrayOutputStream.writeBytes(privateKey.getPublicKey().getCompressedPublicKey());
        }
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened) throws NoSuchAlgorithmException {
        byte[] chainCode = ByteUtils.subArray(key, 32, key.length);
        byte[] keyBytes = ByteUtils.subArray(key, 0, 32);
        BigInteger actualIndex = index;
        if (isHardened) {
            actualIndex = actualIndex.add(new BigInteger("2147483648"));
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(0);
            data.writeBytes(keyBytes);
            data.writeBytes(BigIntegers.asUnsignedByteArray(4, actualIndex));
            byte[] rawKey = HMacSha512.hash(chainCode, data.toByteArray());
            byte[] childRawKey = ByteUtils.subArray(rawKey, 0, 32);
            byte[] childChainCode = ByteUtils.subArray(rawKey, 32, key.length);
            byte[] childKey = BigIntegers.asUnsignedByteArray(
                new BigInteger(1, childRawKey).add(new BigInteger(1, keyBytes)).mod(SecP256K1Constants.order)
            );
            PrivateKey privateKey = new PrivateKey(new BigInteger(1, keyBytes));
            String childFingerprint = Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey()).substring(0, 8);
            return ExtendedKey.from(
                ByteUtils.concatenate(childKey, childChainCode),
                isPrivate,
                "mainnet",
                new BigInteger(depth).add(ONE).longValueExact(),
                childFingerprint,
                actualIndex
            );
        }
        return null;
    }

    public byte[] getKey() {
        return key;
    }

}
