# bitcoin-java
A Bitcoin Library written in Java

# Installing with Maven
Add the following dependency to your pom.xml:

```
<dependency>
    <groupId>io.github.bitcoin-education</groupId>
    <artifactId>bitcoin-java</artifactId>
    <version>0.1.0</version>
</dependency>
```

Add the following plugin goal:

```
<build>
    <plugins>
        <plugin>
            <artifactId>maven-dependency-plugin</artifactId>
            <executions>
                <execution>
                    <phase>compile</phase>
                    <goals>
                        <goal>unpack</goal>
                    </goals>
                    <configuration>
                        <artifactItems>
                            <artifactItem>
                                <groupId>io.github.bitcoin-education</groupId>
                                <artifactId>bitcoin-java</artifactId>
                                <version>0.1.0</version>
                                <overWrite>true</overWrite>
                                <outputDirectory>${project.build.directory}/classes</outputDirectory>
                                <destFileName>wordlist.txt</destFileName>
                                <includes>**/*.txt</includes>
                            </artifactItem>
                        </artifactItems>
                    </configuration>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

#Usage
##Deriving an address, creating and signing a transaction on testnet

```
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.bitcoineducation.bitcoinjava.*;
import org.bouncycastle.util.encoders.Hex;

public class Example {
    public static void main(String[] args) throws IOException {

        Security.addProvider(new BouncyCastleProvider()); // Bitcoin java uses the library Bouncy Castle to provide cryptography functions, so we add its provider to Java Security

        String secret = "1234fafafaef";
        System.out.println("Private Key for input: " + secret);

        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(secret))); // We convert the hexadecimal secret to a BigInteger before passing it to the PrivateKey's constructor
        System.out.println("Address for input: " + privateKey.getPublicKey().addressFromCompressedPublicKey(AddressConstants.TESTNET_P2PKH_ADDRESS_PREFIX)); // We are making a testnet transaction

        // Output:
        // Private Key for input: 1234fafafaef
        // Address for input: ms8L97CtBHV3qU2AGzpKnRYFyyv5WbMcR7

        String inputTransactionId = "3727aacf19dea8bbb5cb284862d152da75475b3f503726b244d5463487770587";

        String receivingAddress = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt";

        BigInteger inputTransactionIndex = BigInteger.ONE;

        TransactionInput transactionInput = new TransactionInput(
            inputTransactionId,
            inputTransactionIndex,
            new Script(List.of()), // Since we are building an unsigned transaction input (it will be signed later), we pass an empty script sig here
            new BigInteger(1, Hex.decode("ffffffff")) // This is a default value used for transactions like this
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput); // Transactions can have many inputs. In our case, it has only one

        BigInteger amount = BigInteger.valueOf(90000); // We choose an amount to send in satoshis
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2pkhScript(Base58.decodeWithChecksumToHex(receivingAddress))); // The method p2pkhScript will make the scriptPubkey for the output
        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput); // Transactions can have many outputs. In our case, it has only one. If you need change for your transaction, add another output to the list

        Transaction transaction = new Transaction(
            BigInteger.ONE, // Transaction version, we set it equal to one for this type of transaction
            transactionInputArrayList,
            transactionOutputArrayList,
            BigInteger.ZERO, // Locktime, we set it equal to zero for this type of transaction
            false // We are not making a Segwit transaction, so we set it to false
        );
        System.out.println("Unsigned transaction: " + transaction.serialize());

        // Output:
        // Unsigned transaction: 0100000001870577873446d544b22637503f5b4775da52d1624828cbb5bba8de19cfaa27370100000000ffffffff01905f0100000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688ac00000000

        TransactionECDSASigner.sign( // This method will modify the transaction object, including the signature in it. We have to call it for each transaction input.
            transaction,
            privateKey, // The private key used to generate the address from the input we are signing
            0, // Index of the input we are signing
            null, // Since it is not a Segwit input, we don't need to include an amount
            false // Since it is not a Segwit input, we set it to false
        );
        System.out.println("Signed transaction: " + transaction.serialize());

        // Output:
        // Signed transaction: 0100000001870577873446d544b22637503f5b4775da52d1624828cbb5bba8de19cfaa2737010000006b4830450221009ccad8f398747aa914806a1eda45ca61fafc79b274ae5fce7baf78b60d25d224022022689efe6f39dc56f055c018e4814916603b97fc462d2d8f3782a6e2a04ab34e012102d8c71893d547187848e311caedf4b7cbfbc38f13ea5641e8a20b1fa637bbbac6ffffffff01905f0100000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688ac00000000

        System.out.println("Transaction id: " + transaction.id());
    }
}
```

More examples at https://github.com/bitcoin-education/bitcoin-java/tree/main/src/main/java/examples 

#Website
https://www.bitcoineducation.site/