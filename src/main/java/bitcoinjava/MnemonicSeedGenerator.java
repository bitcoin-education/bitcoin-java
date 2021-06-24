package bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class MnemonicSeedGenerator {
    public static MnemonicSeed generateRandom(int strength) throws NoSuchAlgorithmException, IOException, URISyntaxException {
        if (!List.of(128, 160, 192, 224, 256).contains(strength)) {
            throw new IllegalArgumentException("Strength not allowed, must be one of: 128, 160, 192, 224 or 256");
        }
        byte[] entropy = randomEntropy(strength / 8);
        return fromEntropy(entropy);
    }

    public static MnemonicSeed fromEntropy(byte[] entropy) throws NoSuchAlgorithmException, IOException, URISyntaxException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sha256Entropy = sha256.digest(entropy);
        int checksumSize = entropy.length * 8 / 32;
        int checksum = BitsConverter.convertBits(sha256Entropy, 8, checksumSize, true).get(0);
        checksum <<= 8 - checksumSize;

        byte[] combined = ByteUtils.concatenate(entropy, new byte[]{(byte) checksum});

        List<Integer> indexes = BitsConverter.convertBits(combined, 8, 11, false);

        URI path = Objects.requireNonNull(MnemonicSeedGenerator.class.getClassLoader().getResource("wordlist.txt")).toURI();
        List<String> wordlist = Files.readAllLines(Path.of(path));

        return new MnemonicSeed(indexes.stream().map(wordlist::get).collect(Collectors.joining(" ")));
    }

    private static byte[] randomEntropy(int strength) {
        byte[] entropy = new byte[strength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(entropy);
        return entropy;
    }

}
