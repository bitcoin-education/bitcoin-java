import bitcoinjava.Bech32;
import bitcoinjava.PublicKey;
import bitcoinjava.Script;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.stream.Stream;

import static bitcoinjava.AddressConstants.MAINNET_P2WPKH_ADDRESS_PREFIX;
import static bitcoinjava.PublicKey.taprootInternalKeyFromX;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PublicKeyTest {
    @ParameterizedTest
    @MethodSource("taprootAddressParameters")
    public void taprootAddress(String internalKeyX, String expectedAddress) {
        PublicKey internalKey = taprootInternalKeyFromX(new BigInteger(1, Hex.decode(internalKeyX)));
        PublicKey outputKey = internalKey.toTaprootSingleKeyOutputKey();
        assertEquals(expectedAddress, outputKey.taprootAddress(MAINNET_P2WPKH_ADDRESS_PREFIX));
    }

    private static Stream<Arguments> taprootAddressParameters() {
        return Stream.of(
            Arguments.of(
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
            ),
            Arguments.of(
                "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
            ),
            Arguments.of(
                "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
            )
        );
    }

}
