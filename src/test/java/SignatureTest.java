import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import io.github.bitcoineducation.bitcoinjava.Signature;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignatureTest {
    @Test
    public void testDerSignature() throws IOException {
        Signature signature = new Signature(
            new BigInteger(1, Hex.decodeStrict("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6")),
            new BigInteger(1, Hex.decodeStrict("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"))
        );
        assertEquals("3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", signature.derHex());
    }

}
