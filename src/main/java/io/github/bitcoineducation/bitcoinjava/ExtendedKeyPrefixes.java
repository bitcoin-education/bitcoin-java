package io.github.bitcoineducation.bitcoinjava;

public class ExtendedKeyPrefixes {
    public static final ExtendedKeyPrefix MAINNET_PREFIX = new ExtendedKeyPrefix("0488ADE4", "0488B21E");
    public static final ExtendedKeyPrefix TESTNET_PREFIX = new ExtendedKeyPrefix("04358394", "043587CF");
    public static final ExtendedKeyPrefix MAINNET_NESTED_SEGWIT_PREFIX = new ExtendedKeyPrefix("049D7878", "049D7CB2");
    public static final ExtendedKeyPrefix TESTNET_NESTED_SEGWIT_PREFIX = new ExtendedKeyPrefix("044A4E28", "044A5262");
    public static final ExtendedKeyPrefix MAINNET_SEGWIT_PREFIX = new ExtendedKeyPrefix("04B2430C", "04B24746");
    public static final ExtendedKeyPrefix TESTNET_SEGWIT_PREFIX = new ExtendedKeyPrefix("045F18BC", "045F1CF6");
}
