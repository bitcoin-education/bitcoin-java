package io.github.bitcoineducation.bitcoinjava;

public class ExtendedKeyPrefix {
    private final String privatePrefix;
    private final String publicPrefix;

    public ExtendedKeyPrefix(String privatePrefix, String publicPrefix) {
        this.privatePrefix = privatePrefix;
        this.publicPrefix = publicPrefix;
    }

    public String getPrivatePrefix() {
        return privatePrefix;
    }

    public String getPublicPrefix() {
        return publicPrefix;
    }
}
