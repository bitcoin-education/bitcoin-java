package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;

public class ExtendedPubkey implements ExtendedKey {
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

    public static ExtendedPubkey fromPrivate(byte[] key, long depth, String fingerprint, BigInteger childNumber, String prefix) {
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

    public static ExtendedPubkey fromPublic(byte[] key, long depth, String fingerprint, BigInteger childNumber, String prefix) {
        return new ExtendedPubkey(
            key,
            prefix,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(1, valueOf(depth))),
            fingerprint,
            Hex.toHexString(BigIntegers.asUnsignedByteArray(4, childNumber))
        );
    }

    public String serialize() {
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

    public static ExtendedPubkey unserialize(String serialized) throws IOException {
        byte[] bytes = Base58.decodeExtendedKey(serialized);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        byte[] prefixBytes = byteArrayInputStream.readNBytes(4);
        byte[] depthBytes = byteArrayInputStream.readNBytes(1);
        byte[] fingerprintBytes = byteArrayInputStream.readNBytes(4);
        byte[] childNumberBytes = byteArrayInputStream.readNBytes(4);
        byte[] chainCodeBytes = byteArrayInputStream.readNBytes(32);
        byte[] keyBytes = byteArrayInputStream.readNBytes(33);
        byte[] combinedKey = ByteUtils.concatenate(keyBytes, chainCodeBytes);
        return new ExtendedPubkey(
            combinedKey,
            Hex.toHexString(prefixBytes),
            Hex.toHexString(depthBytes),
            Hex.toHexString(fingerprintBytes),
            Hex.toHexString(childNumberBytes)
        );
    }

    @Override
    public ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened, String prefix) {
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
            depth,
            childFingerprint,
            index,
            prefix
        );
    }

    public ExtendedKey ckd(String derivationPath) {
        return ckd(derivationPath, prefix);
    }

    public ExtendedKey ckd(String derivationPath, String prefix) {
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
                prefix
            );
        }
        return extendedKey;
    }

    @Override
    public PublicKey toPublicKey() {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 33);
        return PublicKey.fromCompressedPublicKey(keyBytes);
    }

}
