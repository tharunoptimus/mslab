public class Transposition {
    // the most simplest code for transposition cipher
    public static String encrypt(String plainText, int key) {
        char[][] railMatrix = new char[key][plainText.length()];
        for (int i = 0; i < railMatrix.length; i++) {
            for (int j = 0; j < railMatrix[i].length; j++) {
                railMatrix[i][j] = '\n';
            }
        }
        boolean down = false;
        int row = 0, col = 0;
        for (int i = 0; i < plainText.length(); i++) {
            if (row == 0 || row == key - 1) {
                down = !down;
            }
            railMatrix[row][col++] = plainText.charAt(i);
            if (down) {
                row++;
            } else {
                row--;
            }
        }
        String cipherText = "";
        for (int i = 0; i < key; i++) {
            for (int j = 0; j < plainText.length(); j++) {
                if (railMatrix[i][j] != '\n') {
                    cipherText += railMatrix[i][j];
                }
            }
        }
        return cipherText;
    }  
    
    public static String decrypt(String cipherText, int key) {
        char[][] railMatrix = new char[key][cipherText.length()];
        for (int i = 0; i < railMatrix.length; i++) {
            for (int j = 0; j < railMatrix[i].length; j++) {
                railMatrix[i][j] = '\n';
            }
        }
        boolean down = false;
        int row = 0, col = 0;
        for (int i = 0; i < cipherText.length(); i++) {
            if (row == 0 || row == key - 1) {
                down = !down;
            }
            railMatrix[row][col++] = '*';
            if (down) {
                row++;
            } else {
                row--;
            }
        }
        int index = 0;
        for (int i = 0; i < key; i++) {
            for (int j = 0; j < cipherText.length(); j++) {
                if (railMatrix[i][j] == '*' && index < cipherText.length()) {
                    railMatrix[i][j] = cipherText.charAt(index++);
                }
            }
        }
        String plainText = "";
        row = 0;
        col = 0;
        for (int i = 0; i < cipherText.length(); i++) {
            if (row == 0 || row == key - 1) {
                down = !down;
            }
            if (railMatrix[row][col] != '*') {
                plainText += railMatrix[row][col++];
            }
            if (down) {
                row++;
            } else {
                row--;
            }
        }
        return plainText;
    }

    public static void main(String[] args) {
        String plainText = "Hello World";
        int key = 3;
        String cipherText = encrypt(plainText, key);
        System.out.println("Plain Text: " + plainText);
        System.out.println("Cipher Text: " + cipherText);
        System.out.println("Plain Text: " + decrypt(cipherText, key));
    }
}
