import java.math.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

class SHA {
    public static byte[] getSHA(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHexString(byte[] hash) {
        BigInteger number = new BigInteger(1, hash);

        StringBuilder hexString = new StringBuilder(number.toString(16));

        while (hexString.length() < 64) {
            hexString.insert(0, '0');
        }

        return hexString.toString();
    }

    


    public static void main(String args[]) {
        try {
            String string = "Meow Meow";
            System.out.println(string + " : " + toHexString(getSHA(string)));
        }

        catch (Exception e) {
            System.out.println("Something Went Wrong: " + e);
        }
    }
}
