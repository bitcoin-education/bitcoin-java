import io.github.bitcoineducation.bitcoinjava.P2WSHTransactionECDSASigner;
import io.github.bitcoineducation.bitcoinjava.PrivateKey;
import io.github.bitcoineducation.bitcoinjava.Script;
import io.github.bitcoineducation.bitcoinjava.Transaction;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import static io.github.bitcoineducation.bitcoinjava.OpCodes.*;
import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class P2WSHTransactionECDSASignerTest {
    @Test
    public void signOneOfTwoMultisig() throws IOException {
        String txHex = "0100000000010119337379307b03a59496cf15dfd05036c3bd1797ac021d9dc857eb9c93ae71840100000000ffffffff01d07e0100000000002200205f7fe05a32c991d0de09ed75609d839d8c304a6f4ce57924a3acc8d3f1c197d60300483045022100bae81df3c4dfc0b05db401f299b9ce211b7c22559e7431cbeb24c3a7a39d2e2102206eb4e450999658b7cfeb21444d1dd9940ae6cbd4638123bd47fdd6bba4de066f0147512103812f5f8f94738078f36c3516cfd8444dba18f447104215efa1f9e9e165c7a98e21023dedc63f46164527339ed37d4a1e63d361629968ca1ab21d159e79641356272a52ae00000000";
        Transaction expectedTransaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));

        String unsignedTxHex = "0100000000010119337379307b03a59496cf15dfd05036c3bd1797ac021d9dc857eb9c93ae71840100000000ffffffff01d07e0100000000002200205f7fe05a32c991d0de09ed75609d839d8c304a6f4ce57924a3acc8d3f1c197d60000000000";
        Transaction unsignedTransaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(unsignedTxHex)));

        String secret = "75a0c09158b643779a11e3e2c512e1c1";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        String secret2 = "b590963c9f1543c88207509e4e98a086";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));
        Script redeemScript = new Script(List.of(valueOf(OP_1), privateKey1.getPublicKey().compressedPublicKeyHex(), privateKey2.getPublicKey().compressedPublicKeyHex(), valueOf(OP_2), valueOf(OP_CHECKMULTISIG)));

        P2WSHTransactionECDSASigner.partialSign(unsignedTransaction, privateKey1, 0, redeemScript, BigInteger.valueOf(100_000));
        P2WSHTransactionECDSASigner.appendRedeemScript(unsignedTransaction,0, redeemScript);

        assertEquals(expectedTransaction.serialize(), unsignedTransaction.serialize());
    }
}
