import bitcoinjava.PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import bitcoinjava.PrivateKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.Security;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PrivateKeyTest {
    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testUncompressedPublicKeyHex1() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(5000));
        assertEquals(
            "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10",
            privateKey.getPublicKey().uncompressedPublicKeyHex()
        );
        assertEquals(
            privateKey.getPublicKey().uncompressedPublicKeyHex(),
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).uncompressedPublicKeyHex()
        );
    }

    @Test
    public void testUncompressedPublicKeyHex2() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(2018).pow(5));
        assertEquals(
            "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06",
            privateKey.getPublicKey().uncompressedPublicKeyHex()
        );
    }

    @Test
    public void testUncompressedPublicKeyHex3() {
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decodeStrict("0deadbeef12345")));
        assertEquals(
            "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121",
            privateKey.getPublicKey().uncompressedPublicKeyHex()
        );
    }

    @Test
    public void testCompressedPublicKeyHex1() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(5001));
        assertEquals(
            "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1",
            privateKey.getPublicKey().compressedPublicKeyHex()
        );
        assertEquals(
            "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1",
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
        );
    }

    @Test
    public void testCompressedPublicKeyHex2() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(2019).pow(5));
        assertEquals(
            "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701",
            privateKey.getPublicKey().compressedPublicKeyHex()
        );
        assertEquals(
            "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701",
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
        );
    }

    @Test
    public void testCompressedPublicKeyHex3() {
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decodeStrict("0deadbeef54321")));
        assertEquals(
            "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690",
            privateKey.getPublicKey().compressedPublicKeyHex()
        );
        assertEquals(
            "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690",
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
        );
    }

    @Test
    public void testUncompressedPublicKeyAddress() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(5002));
        assertEquals(
            "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA",
            privateKey.getPublicKey().addressFromUncompressedPublicKey("6f")
        );
        assertEquals(
            privateKey.getPublicKey().compressedPublicKeyHex(),
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
        );
    }

    @Test
    public void testCompressedPublicKeyAddress() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(2020).pow(5));
        assertEquals(
            "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH",
            privateKey.getPublicKey().addressFromCompressedPublicKey("6f")
        );
        assertEquals(
            privateKey.getPublicKey().compressedPublicKeyHex(),
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
        );
    }

    @Test
    public void testCompressedPublicKeyAddress2() {
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decodeStrict("012345deadbeef")));
        assertEquals(
            "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1",
            privateKey.getPublicKey().addressFromCompressedPublicKey("00")
        );
        assertEquals(
            privateKey.getPublicKey().compressedPublicKeyHex(),
            PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
        );
    }

    @Test
    public void randomFromCompressedKeyTest() {
        for (int i = 0; i < 100; i++) {
            String secret = UUID.randomUUID().toString().replace("-", "");
            PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
            assertEquals(
                privateKey.getPublicKey().compressedPublicKeyHex(),
                PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).compressedPublicKeyHex()
            );
            assertEquals(
                privateKey.getPublicKey().uncompressedPublicKeyHex(),
                PublicKey.fromCompressedPublicKey(privateKey.getPublicKey().getCompressedPublicKey()).uncompressedPublicKeyHex()
            );
        }
    }

    @Test
    public void testWif1() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(5003));
        assertEquals(
            "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK",
            privateKey.wif("ef", true)
        );
    }

    @Test
    public void testWif2() {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(2021).pow(5));
        assertEquals(
            "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic",
            privateKey.wif("ef", false)
        );
    }

    @Test
    public void testWif3() {
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decodeStrict("054321deadbeef")));
        assertEquals(
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a",
            privateKey.wif("80", true)
        );
    }

    @ParameterizedTest
    @MethodSource("testFromWifParameters")
    public void testFromWif(String wif, boolean compressed) {
        PrivateKey privateKey = PrivateKey.fromWif(wif, compressed);
        assertEquals(wif, privateKey.wif("80", compressed));
    }

    private static Stream<Arguments> testFromWifParameters() {
        return Stream.of(
            Arguments.of(
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a",
                true
            ),
            Arguments.of(
                "5JaTXbAUmfPYZFRwrYaALK48fN6sFJp4rHqq2QSXs8ucfpE4yQU",
                false
            ),
            Arguments.of(
                "5Jb7fCeh1Wtm4yBBg3q3XbT6B525i17kVhy3vMC9AqfR6FH2qGk",
                false
            ),
            Arguments.of(
                "5JFjmGo5Fww9p8gvx48qBYDJNAzR9pmH5S389axMtDyPT8ddqmw",
                false
            )
        );
    }

}
