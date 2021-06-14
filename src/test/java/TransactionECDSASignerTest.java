import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TransactionECDSASignerTest {
    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void sign() throws IOException, NoSuchAlgorithmException {
        PrivateKey privateKey = new PrivateKey(BigInteger.valueOf(8675309));
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Hex.decode("010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000"));
        Transaction transaction = Transaction.fromByteStream(byteArrayInputStream);
        TransactionECDSASigner.sign(transaction, privateKey, 0, null, false);
        String expectedTransaction = "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d0000006b4830450221008ed46aa2cf12d6d81065bfabe903670165b538f65ee9a3385e6327d80c66d3b502203124f804410527497329ec4715e18558082d489b218677bd029e7fa306a72236012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000";
        assertEquals(expectedTransaction, transaction.serialize());
    }

    @Test
    public void signSegwit() throws IOException, NoSuchAlgorithmException {
        PrivateKey privateKey = new PrivateKey(new BigInteger("61246911195951955945444562903070884624662294596119750503704480515277775165366"));
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Hex.decode("02000000000101f906aca439eacb48279bdc3e9d688ccffd708147c0c785c56cc0ea6c5230091d0100000000ffffffff02204e0000000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688acf06900000000000016001418e945153f5043f929c08d9df8c1d9a1e494acf0024800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000021023463977db0bebb55c248e3091cb7e75745177490d3ea19d75999633ddf4cc99900000000"));
        Transaction transaction = Transaction.fromByteStream(byteArrayInputStream);
        TransactionECDSASigner.sign(transaction, privateKey, 0, BigInteger.valueOf(47264), true);
        String expectedTransaction = "02000000000101f906aca439eacb48279bdc3e9d688ccffd708147c0c785c56cc0ea6c5230091d0100000000ffffffff02204e0000000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688acf06900000000000016001418e945153f5043f929c08d9df8c1d9a1e494acf00247304402201989711f20a1cac23a66cf19fffba0e994a3b3b9b11f9778e3bff18e8bf44edb02203c2debdef4c1388f343a983122e63fef7a9e27bf9667da198367b70ca804ad600121023463977db0bebb55c248e3091cb7e75745177490d3ea19d75999633ddf4cc99900000000";
        assertEquals(expectedTransaction, transaction.serialize());
    }
}
