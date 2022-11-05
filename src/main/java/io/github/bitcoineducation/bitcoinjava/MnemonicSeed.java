package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
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

    public ExtendedPrivateKey toMasterKey(String passphrase, String prefix) {
        return ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", toSeed(passphrase)),
            0,
            "00000000",
            BigInteger.ZERO,
            prefix
        );
    }

    public byte[] toEntropy() {
        InputStream inputStream = Objects.requireNonNull(MnemonicSeedGenerator.class.getClassLoader().getResourceAsStream("wordlist.txt"));
        List<String> wordlist = new BufferedReader(new InputStreamReader(inputStream)).lines().collect(Collectors.toList());

        String[] mnemonicSeedList = sentence.split(" ");

        List<Integer> indexesList = Arrays.stream(mnemonicSeedList).map(wordlist::indexOf).collect(Collectors.toList());
        List<Integer> indexes = BitsConverter.convertBits(indexesList, 11, 8, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        indexes.forEach(byteArrayOutputStream::write);
        byte[] combined = byteArrayOutputStream.toByteArray();

        return ByteUtils.subArray(combined, 0, combined.length - 1);
    }
}
