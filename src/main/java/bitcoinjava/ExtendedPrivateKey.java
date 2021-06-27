package bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;

public class ExtendedPrivateKey implements ExtendedKey {
    public static final String MAINNET_PRIVATE_PREFIX = "0488ADE4";
    public static final String TESTNET_PRIVATE_PREFIX = "04358394";

    private final byte[] key;

    private final String prefix;

    private final String fingerprint;

    private final String depth;

    private final String childNumber;

    private ExtendedPrivateKey(byte[] key, String prefix, String depth, String fingerprint, String childNumber) {
        this.key = key;
        this.prefix = prefix;
        this.depth = depth;
        this.fingerprint = fingerprint;
        this.childNumber = childNumber;
    }

    public static ExtendedPrivateKey from(byte[] key, String environment, long depth, String fingerprint, BigInteger childNumber) {
        String prefix;
        if (environment.equals("mainnet")) {
            prefix = MAINNET_PRIVATE_PREFIX;
        } else if (environment.equals("testnet")) {
            prefix = TESTNET_PRIVATE_PREFIX;
        } else {
            throw new IllegalArgumentException("Invalid environment, must be testnet or mainnet");
        }

        int keyBytesLength = 32 - (64 - key.length);
        byte[] keyBytes = ByteUtils.subArray(key, 0, keyBytesLength);
        byte[] chainCode = ByteUtils.subArray(key, keyBytesLength, key.length);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int keyLength = keyBytes.length;
        while (keyLength < 32) {
            byteArrayOutputStream.write(0);
            keyLength++;
        }
        byteArrayOutputStream.writeBytes(keyBytes);
        byteArrayOutputStream.writeBytes(chainCode);

        return new ExtendedPrivateKey(
            byteArrayOutputStream.toByteArray(),
            prefix,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(1, valueOf(depth))),
            fingerprint,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(4, childNumber))
        );
    }

    @Override
    public String serialize() throws NoSuchAlgorithmException {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 32);
        byte[] chainCode = ByteUtils.subArray(key, 32, key.length);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decode(prefix));
        byteArrayOutputStream.writeBytes(Hex.decode(depth));
        byteArrayOutputStream.writeBytes(Hex.decode(fingerprint));
        byteArrayOutputStream.writeBytes(Hex.decode(childNumber));
        byteArrayOutputStream.writeBytes(chainCode);
        byteArrayOutputStream.writeBytes(Hex.decode("00"));
        byteArrayOutputStream.writeBytes(keyBytes);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened, String environment) throws NoSuchAlgorithmException {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 32);
        byte[] chainCode = ByteUtils.subArray(key, 32, key.length);
        BigInteger actualIndex = index;
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        byte[] rawKey;
        PublicKey publicKey = new PrivateKey(new BigInteger(1, keyBytes)).getPublicKey();
        if (isHardened) {
            actualIndex = actualIndex.add(new BigInteger("2147483648"));
            data.write(0);
            data.writeBytes(keyBytes);
        } else {
            data.writeBytes(publicKey.getCompressedPublicKey());
        }
        data.writeBytes(BigIntegers.asUnsignedByteArray(4, actualIndex));
        rawKey = HMacSha512.hash(chainCode, data.toByteArray());

        byte[] childRawKey = ByteUtils.subArray(rawKey, 0, 32);
        byte[] childChainCode = ByteUtils.subArray(rawKey, 32, rawKey.length);
        byte[] childKey = BigIntegers.asUnsignedByteArray(
            new BigInteger(1, childRawKey).add(new BigInteger(1, keyBytes)).mod(SecP256K1.order)
        );
        String childFingerprint = Hash160.hashToHex(publicKey.getCompressedPublicKey()).substring(0, 8);
        long depth = new BigInteger(this.depth).add(ONE).longValueExact();
        if (isPrivate) {
            return ExtendedPrivateKey.from(
                ByteUtils.concatenate(childKey, childChainCode),
                environment,
                depth,
                childFingerprint,
                actualIndex
            );
        }
        return ExtendedPubkey.fromPrivate(
            ByteUtils.concatenate(childKey, childChainCode),
            environment,
            depth,
            childFingerprint,
            actualIndex
        );
    }

    public ExtendedKey ckd(String derivationPath, boolean isPrivate, String environment) throws NoSuchAlgorithmException {
        String[] indexes = derivationPath.split("/");
        ExtendedKey extendedKey = this;
        for (int i = 0, indexesLength = indexes.length; i < indexesLength; i++) {
            boolean privateIteration = true;
            if (i == indexesLength - 1 && !isPrivate) {
                privateIteration = false;
            }
            String index = indexes[i];
            if (index.endsWith("'")) {
                extendedKey = extendedKey.ckd(
                    new BigInteger(index.replace("'", "")),
                    privateIteration,
                    true,
                    environment
                );
                continue;
            }
            extendedKey = extendedKey.ckd(
                new BigInteger(index),
                privateIteration,
                false,
                environment
            );
        }
        return extendedKey;
    }

    public byte[] getKey() {
        return key;
    }

}
