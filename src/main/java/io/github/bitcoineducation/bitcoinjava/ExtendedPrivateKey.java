package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;

public class ExtendedPrivateKey implements ExtendedKey {
    public static final String MAINNET_PRIVATE_PREFIX = "0488ADE4";
    public static final String TESTNET_PRIVATE_PREFIX = "04358394";
    public static final String MAINNET_PRIVATE_NESTED_SEGWIT_PREFIX = "049D7878";
    public static final String TESTNET_PRIVATE_NESTED_SEGWIT_PREFIX = "044A4E28";
    public static final String MAINNET_PRIVATE_SEGWIT_PREFIX = "04B2430C";
    public static final String TESTNET_PRIVATE_SEGWIT_PREFIX = "045F18BC";

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

    public static ExtendedPrivateKey from(byte[] key, long depth, String fingerprint, BigInteger childNumber, String prefix) {
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
    public String serialize() {
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

    public static ExtendedPrivateKey unserialize(String serialized) throws IOException {
        byte[] bytes = Base58.decodeExtendedKey(serialized);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        byte[] prefixBytes = byteArrayInputStream.readNBytes(4);
        byte[] depthBytes = byteArrayInputStream.readNBytes(1);
        byte[] fingerprintBytes = byteArrayInputStream.readNBytes(4);
        byte[] childNumberBytes = byteArrayInputStream.readNBytes(4);
        byte[] chainCodeBytes = byteArrayInputStream.readNBytes(32);
        byteArrayInputStream.skip(1);
        byte[] keyBytes = byteArrayInputStream.readNBytes(32);
        byte[] combinedKey = ByteUtils.concatenate(keyBytes, chainCodeBytes);
        return new ExtendedPrivateKey(
            combinedKey,
            Hex.toHexString(prefixBytes),
            Hex.toHexString(depthBytes),
            Hex.toHexString(fingerprintBytes),
            Hex.toHexString(childNumberBytes)
        );
    }

    public ExtendedKey ckd(BigInteger index, boolean isPrivate, boolean isHardened) {
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
                depth,
                childFingerprint,
                actualIndex,
                ExtendedPrivateKey.MAINNET_PRIVATE_PREFIX);
        }
        return ExtendedPubkey.fromPrivate(
            ByteUtils.concatenate(childKey, childChainCode),
            depth,
            childFingerprint,
            actualIndex,
            ExtendedPubkey.MAINNET_PUBLIC_PREFIX);
    }

    public ExtendedKey ckd(String derivationPath, boolean isPrivate) {
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
                    true
                );
                continue;
            }
            extendedKey = extendedKey.ckd(
                new BigInteger(index),
                privateIteration,
                false
            );
        }
        return extendedKey;
    }

    @Override
    public PublicKey toPublicKey() {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 32);
        return new PrivateKey(new BigInteger(1, keyBytes)).getPublicKey();
    }

    public byte[] getKey() {
        return key;
    }
}
