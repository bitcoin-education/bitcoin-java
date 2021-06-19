package bitcoinjava;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;

public class PublicKey {
    private final byte[] uncompressedPublicKey;

    private final byte[] compressedPublicKey;

    public PublicKey(ECPoint point) {
        this.uncompressedPublicKey = uncompressedPublicKey(point);
        this.compressedPublicKey = compressedPublicKey(point);
    }

    public PublicKey(byte[] compressedPublicKey, byte[] uncompressedPublicKey) {
        this.compressedPublicKey = compressedPublicKey;
        this.uncompressedPublicKey = uncompressedPublicKey;
    }

    private byte[] uncompressedPublicKey(ECPoint point) {
        return point.getEncoded(false);
    }

    private byte[] compressedPublicKey(ECPoint point) {
        return point.getEncoded(true);
    }

    public String uncompressedPublicKeyHex() {
        return Hex.toHexString(uncompressedPublicKey);
    }

    public String compressedPublicKeyHex() {
        return Hex.toHexString(compressedPublicKey);
    }

    public String addressFromUncompressedPublicKey(String prefix) throws NoSuchAlgorithmException {
        byte[] hash160 = Hash160.hash(uncompressedPublicKey);
        return concat(prefix, hash160);
    }

    public String addressFromCompressedPublicKey(String prefix) throws NoSuchAlgorithmException {
        byte[] hash160 = Hash160.hash(compressedPublicKey);
        return concat(prefix, hash160);
    }

    public String segwitAddressFromCompressedPublicKey(String prefix) throws NoSuchAlgorithmException {
        byte[] hash160 = Hash160.hash(compressedPublicKey);
        return Bech32.encode(prefix, 0, hash160);
    }

    private String concat(String prefix, byte[] hash160) throws NoSuchAlgorithmException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decodeStrict(prefix));
        byteArrayOutputStream.writeBytes(hash160);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public byte[] getCompressedPublicKey() {
        return compressedPublicKey;
    }

    public byte[] getUncompressedPublicKey() {
        return uncompressedPublicKey;
    }

}
