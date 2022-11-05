package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.*;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class MnemonicSeedGenerator {
    public static MnemonicSeed generateRandom(int strength) {
        if (!List.of(128, 160, 192, 224, 256).contains(strength)) {
            throw new IllegalArgumentException("Strength not allowed, must be one of: 128, 160, 192, 224 or 256");
        }
        byte[] entropy = randomEntropy(strength / 8);
        MnemonicSeed mnemonicSeed = fromEntropy(entropy);
        check(mnemonicSeed);
        return mnemonicSeed;
    }

    public static MnemonicSeed fromEntropy(byte[] entropy) {
        int checksum = getChecksum(entropy);

        byte[] combined = ByteUtils.concatenate(entropy, new byte[]{(byte) checksum});

        List<Integer> indexes = BitsConverter.convertBits(combined, 8, 11, false);

        List<String> wordlist = loadWordlist();

        return new MnemonicSeed(indexes.stream().map(wordlist::get).collect(Collectors.joining(" ")));
    }

    private static List<String> loadWordlist() {
        InputStream inputStream = Objects.requireNonNull(MnemonicSeedGenerator.class.getClassLoader().getResourceAsStream("wordlist.txt"));
        return new BufferedReader(new InputStreamReader(inputStream, Charset.defaultCharset())).lines().collect(Collectors.toList());
    }

    public static void check(MnemonicSeed mnemonicSeed) {
        assert List.of(12, 15, 18, 21, 24).contains(mnemonicSeed.getSentence().split(" ").length);

        byte[] entropy = mnemonicSeed.toEntropy();
        int checksum = getChecksum(entropy);

        byte[] combined = ByteUtils.concatenate(entropy, new byte[]{(byte) checksum});

        List<Integer> indexes = BitsConverter.convertBits(combined, 8, 11, false);

        List<String> wordlist = loadWordlist();

        assert new MnemonicSeed(indexes.stream().map(wordlist::get).collect(Collectors.joining(" "))).getSentence().equals(mnemonicSeed.getSentence());
    }

    private static int getChecksum(byte[] entropy) {
        byte[] sha256Entropy = Sha256.hash(entropy);
        int checksumSize = entropy.length * 8 / 32;
        int checksum = BitsConverter.convertBits(sha256Entropy, 8, checksumSize, true).get(0);
        checksum <<= 8 - checksumSize;
        return checksum;
    }

    private static byte[] randomEntropy(int strength) {
        byte[] entropy = new byte[strength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(entropy);
        return entropy;
    }

}
