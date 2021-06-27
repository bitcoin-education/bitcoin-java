package bitcoinjava;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.stream.Collectors;

public class MnemonicSeed {
    private final String sentence;

    public MnemonicSeed(String sentence) {
        this.sentence = sentence;
    }

    public String getSentence() {
        return sentence;
    }

    public byte[] toSeed(String passphrase) {
        PKCS5S2ParametersGenerator pkcs5S2ParametersGenerator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA512());
        pkcs5S2ParametersGenerator.init(
            PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(sentence.toCharArray()),
            PBEParametersGenerator.PKCS5PasswordToUTF8Bytes("mnemonic".concat(passphrase).toCharArray()),
            2048
        );
        return ((KeyParameter) pkcs5S2ParametersGenerator.generateDerivedParameters(512)).getKey();
    }

    public String toSeedHex(String passphrase) {
        return Hex.toHexString(toSeed(passphrase));
    }

    public ExtendedPrivateKey toMasterKey(String passphrase, String environment) {
        return ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", toSeed(passphrase)),
            environment,
            0,
            "00000000",
            BigInteger.ZERO
        );
    }

    public byte[] toEntropy() {
        URI path = null;
        try {
            path = Objects.requireNonNull(MnemonicSeedGenerator.class.getClassLoader().getResource("wordlist.txt")).toURI();
        } catch (URISyntaxException e) {
            throw new NoSuchElementException("Could not load wordlist.");
        }
        List<String> wordlist = null;
        try {
            wordlist = Files.readAllLines(Path.of(path));
        } catch (IOException e) {
            throw new NoSuchElementException("Could not load wordlist.");
        }

        String[] mnemonicSeedList = sentence.split(" ");

        List<Integer> indexesList = Arrays.stream(mnemonicSeedList).map(wordlist::indexOf).collect(Collectors.toList());
        List<Integer> indexes = BitsConverter.convertBits(indexesList, 11, 8, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        indexes.forEach(byteArrayOutputStream::write);
        byte[] combined = byteArrayOutputStream.toByteArray();

        return ByteUtils.subArray(combined, 0, combined.length - 1);
    }
}
