import bitcoinjava.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Security;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Base58Test {
    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("encodeTestParameters")
    public void encodeTest(String hexString, String expectedResult) {
        assertEquals(Base58.encodeFromHex(hexString), expectedResult);
    }

    @Test
    public void decodeTest() {
        String hexString = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";
        String expectedResult = "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31";
        assertEquals(expectedResult, Base58.decodeWithChecksumToHex(hexString));
    }

    private static Stream<Arguments> encodeTestParameters() {
        return Stream.of(
            Arguments.of(
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6"
            ),
            Arguments.of(
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd"
            ),
            Arguments.of(
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
                "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7"
            ),
            Arguments.of(
                "",
                ""
            ),
            Arguments.of(
                "61",
                "2g"
            ),
            Arguments.of(
                "626262",
                "a3gV"
            ),
            Arguments.of(
                "636363",
                "aPEr"
            ),
            Arguments.of(
                "73696d706c792061206c6f6e6720737472696e67",
                "2cFupjhnEsSn59qHXstmK2ffpLv2"
            ),
            Arguments.of(
                "00eb15231dfceb60925886b67d065299925915aeb172c06647",
                "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"
            ),
            Arguments.of(
                "516b6fcd0f",
                "ABnLTmg"
            ),
            Arguments.of(
                "bf4f89001e670274dd",
                "3SEo3LWLoPntC"
            ),
            Arguments.of(
                "572e4794",
                "3EFU7m"
            ),
            Arguments.of(
                "ecac89cad93923c02321",
                "EJDM8drfXA6uyA"
            ),
            Arguments.of(
                "10c8511e",
                "Rt5zm"
            ),
            Arguments.of(
                "00000000000000000000",
                "1111111111"
            ),
            Arguments.of(
                "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5",
                "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            ),
            Arguments.of(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY"
            )
        );
    }

}
