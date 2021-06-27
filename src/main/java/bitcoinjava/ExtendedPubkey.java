package bitcoinjava;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;

public class ExtendedPubkey implements ExtendedKey {
    public static final String MAINNET_PUBLIC_PREFIX = "0488B21E";
    public static final String TESTNET_PUBLIC_PREFIX = "043587CF";

    private final byte[] key;

    private final String prefix;

    private final String fingerprint;

    private final String depth;

    private final String childNumber;

    private ExtendedPubkey(byte[] key, String prefix, String depth, String fingerprint, String childNumber) {
        this.key = key;
        this.prefix = prefix;
        this.depth = depth;
        this.fingerprint = fingerprint;
        this.childNumber = childNumber;
    }

    public static ExtendedPubkey fromPrivate(byte[] key, String environment, long depth, String fingerprint, BigInteger childNumber) {
        String prefix;
        if (environment.equals("mainnet")) {
            prefix = MAINNET_PUBLIC_PREFIX;
        } else if (environment.equals("testnet")) {
            prefix = TESTNET_PUBLIC_PREFIX;
        } else {
            throw new IllegalArgumentException("Invalid environment, must be testnet or mainnet");
        }

        int keyBytesLength = 32 - (64 - key.length);
        byte[] keyBytes = ByteUtils.subArray(key, 0, keyBytesLength);
        byte[] chainCode = ByteUtils.subArray(key, keyBytesLength, key.length);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, keyBytes));
        byteArrayOutputStream.writeBytes(privateKey.getPublicKey().getCompressedPublicKey());
        byteArrayOutputStream.writeBytes(chainCode);

        return new ExtendedPubkey(
            byteArrayOutputStream.toByteArray(),
            prefix,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(1, valueOf(depth))),
            fingerprint,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(4, childNumber))
        );
    }

    public static ExtendedPubkey fromPublic(byte[] key, String environment, long depth, String fingerprint, BigInteger childNumber) {
        String prefix;
        if (environment.equals("mainnet")) {
            prefix = MAINNET_PUBLIC_PREFIX;
        } else if (environment.equals("testnet")) {
            prefix = TESTNET_PUBLIC_PREFIX;
        } else {
            throw new IllegalArgumentException("Invalid environment, must be testnet or mainnet");
        }

        return new ExtendedPubkey(
            key,
            prefix,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(1, valueOf(depth))),
            fingerprint,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(4, childNumber))
        );
    }

    public String serialize() throws NoSuchAlgorithmException {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 33);
        byte[] chainCode = ByteUtils.subArray(key, 33, key.length);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decode(prefix));
        byteArrayOutputStream.writeBytes(Hex.decode(depth));
        byteArrayOutputStream.writeBytes(Hex.decode(fingerprint));
        byteArrayOutputStream.writeBytes(Hex.decode(childNumber));
        byteArrayOutputStream.writeBytes(chainCode);
        byteArrayOutputStream.writeBytes(keyBytes);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    @Override
    public ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened, String environment) throws NoSuchAlgorithmException {
        if (isHardened) {
            throw new IllegalArgumentException("Cannot derive hardened key from extended pubkey.");
        }
        if (isPrivate) {
            throw new IllegalArgumentException("Cannot derive private key from extended pubkey.");
        }
        byte[] keyBytes = ByteUtils.subArray(key, 0, 33);
        byte[] chainCode = ByteUtils.subArray(key, 33, key.length);
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.writeBytes(keyBytes);
        data.writeBytes(BigIntegers.asUnsignedByteArray(4, index));

        byte[] rawKey = HMacSha512.hash(chainCode, data.toByteArray());
        byte[] childRawKey = ByteUtils.subArray(rawKey, 0, 32);
        byte[] childChainCode = ByteUtils.subArray(rawKey, 32, rawKey.length);

        PublicKey childPublicKey = new PrivateKey(new BigInteger(1, childRawKey)).getPublicKey();
        PublicKey publicKey = PublicKey.fromCompressedPublicKey(keyBytes);
        ECPoint point = childPublicKey.getPoint().add(publicKey.getPoint());
        byte[] childKey = point.getEncoded(true);

        String childFingerprint = Hash160.hashToHex(keyBytes).substring(0, 8);
        long depth = new BigInteger(this.depth).add(ONE).longValueExact();
        return ExtendedPubkey.fromPublic(
            ByteUtils.concatenate(childKey, childChainCode),
            environment,
            depth,
            childFingerprint,
            index
        );
    }

    public ExtendedKey ckd(String derivationPath, String environment) throws NoSuchAlgorithmException {
        String[] indexes = derivationPath.split("/");
        ExtendedKey extendedKey = this;
        for (String index : indexes) {
            if (index.endsWith("'")) {
                throw new IllegalArgumentException("Cannot derive hardened key from extended pubkey.");
            }
            extendedKey = extendedKey.ckd(
                new BigInteger(index),
                false,
                false,
                environment
            );
        }
        return extendedKey;
    }
}
