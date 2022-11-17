import java.security.*;

public class DSA {

    public static void main(String args[]) {
        try {
            SignerUser signer = new SignerUser();
            String message = "Every sunset give us one day less to live. But every sunrise give uso ne day more to hope.";

            byte[] sign = signMessage(message.getBytes(), signer.getPrivateKey());

            PublicKey pubKey = signer.getPubKey();

            System.out.println("--- Example with a valid signature ---");
            validateMessageSignature(pubKey, message.getBytes(), sign);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void validateMessageSignature(PublicKey publicKey, byte[] message, byte[] signature)
            throws Exception {
        Signature clientSig = Signature.getInstance("DSA");
        clientSig.initVerify(publicKey);
        clientSig.update(message);
        if (clientSig.verify(signature)) {
            System.out.println("The message is properly signed.");
        } else {
            System.err.println("It is not possible to validate the signature.");
        }
    }

    public static byte[] signMessage(byte[] message, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("DSA");
        sig.initSign(privateKey);
        sig.update(message);
        byte[] sign = sig.sign();
        return sign;
    }

    public static class SignerUser {
        private PublicKey publicKey;
        private PrivateKey privateKey;

        public PublicKey getPubKey() {
            return publicKey;
        }

        public SignerUser() throws NoSuchAlgorithmException {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            SecureRandom secRan = new SecureRandom();
            kpg.initialize(512, secRan);
            KeyPair keyP = kpg.generateKeyPair();
            this.publicKey = keyP.getPublic();
            this.privateKey = keyP.getPrivate();
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

    }
}