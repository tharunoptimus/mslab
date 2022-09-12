# Code:

```java

import java.util.Scanner;

public class HillCipher {
    static String alphabet = "abcdefghijklmnopqrstuvwxyz";
    private static Scanner sc;

    public static int check(int a) {
        while (a < 0)
            a += 26;
        return a;
    }

    public static int[][] multiply(int r, int nc, int a[][], int b[][]) {
        int c[][] = new int[r][nc];
        for (int i = 0; i < r; i++)
            for (int j = 0; j < nc; j++) {
                c[i][j] = 0;
                for (int k = 0; k < r; k++) {
                    c[i][j] += (a[i][k] * b[k][j]);
                }
                c[i][j] %= 26;
                while (c[i][j] < 0)
                    c[i][j] += 26;
            }
        return c;
    }

    public static int gcd(int a, int b) {
        if (b == 0)
            return a;
        return gcd(b, a % b);
    }

    public static int inverse(int a) {
        int q, r1 = 26, r2 = a, r, t1 = 0, t2 = 1, t;
        while (r2 > 0) {
            q = r1 / r2;
            r = r1 % r2;
            t = t1 - q * t2;
            t1 = t2;
            t2 = t;
            r1 = r2;
            r2 = r;
        }
        if (t1 < 0)
            t1 = t1 + 26;
        return t1;
    }

    public static void main(String[] args) {
        sc = new Scanner(System.in);
        String plaintext, encrypt, decrypt;
        System.out.println("Enter the plaintext to be encrypted:");
        plaintext = sc.nextLine();
        encrypt = "";
        decrypt = "";
        int r = 0, c = 0, kd = 0, ch = 1;
        while (ch == 1) {
            System.out.println("Enter the row and column of key matrix:");
            r = sc.nextInt();
            c = sc.nextInt();
            if ((r == 2 && c == 2) || (r == 3 && c == 3))
                ch = 0;
            else
                System.out.println("Enter the valid row and column");
        }
        int k[][], ki[][], kdi;
        if (r == 2)
            k = new int[2][2];
        else
            k = new int[3][3];
        ch = 1;
        while (ch == 1) {
            if (r == 2 && c == 2) {

                System.out.println("Enter the key matrix:(0-25)");
                for (int i = 0; i < r; i++)
                    for (int j = 0; j < c; j++)
                        k[i][j] = sc.nextInt();
                kd = (k[0][0] * k[1][1]) - (k[0][1] * k[1][0]);
                kd %= 26;
                while (kd < 0)
                    kd += 26;
                // System.out.println("d: "+kd);

                if (gcd(kd, 26) == 1)
                    ch = 0;
                else
                    System.out.println("Enter a valid key matrix");
            } else if (r == 3 && c == 3) {
                System.out.println("Enter the key matrix:(0-25)");
                for (int i = 0; i < r; i++)
                    for (int j = 0; j < c; j++)
                        k[i][j] = sc.nextInt();
                kd = (k[0][0] * k[1][1] * k[2][2]) - (k[0][0] * k[1][2] * k[2][1]) + (k[0][1] * k[1][2] * k[2][0])
                        - (k[0][1] * k[1][0] * k[2][2]) + (k[0][2] * k[1][0] * k[2][1]) - (k[0][2] * k[1][1] * k[2][0]);
                kd %= 26;
                while (kd < 0)
                    kd += 26;
                if (gcd(kd, 26) == 1)
                    ch = 0;
                else
                    System.out.println("Enter a valid key matrix");
                // System.out.println("d:"+kd);
                // System.out.println("d:"+(kd%26));
            }
        }
        int p[][], e[][], d[][];
        if (r == 2 && c == 2) {
            int nc;
            if (plaintext.length() % 2 == 0) {
                nc = plaintext.length() / 2;
                p = new int[2][nc];
            } else {
                nc = plaintext.length() / 2 + 1;
                p = new int[2][nc];
            }
            // System.out.println(nc);
            int l = 0;
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < r; j++) {
                    if (i == nc - 1 && j == r - 1 && (plaintext.length() % 2 == 1))
                        p[j][i] = alphabet.indexOf('x');
                    else
                        p[j][i] = alphabet.indexOf(plaintext.charAt(l++));
                    // System.out.print(p[j][i]+" ");
                }
            // System.out.println("\n");
            e = new int[r][nc];
            e = multiply(r, nc, k, p);
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < r; j++) {
                    encrypt += alphabet.charAt(e[j][i]);
                }
            System.out.println("Encrypted text: " + encrypt);
            ki = new int[2][2];
            kdi = inverse(kd);
            // System.out.println("di: "+kdi);
            ki[0][0] = kdi * k[1][1] % 26;
            ki[1][1] = kdi * k[0][0] % 26;
            ki[0][1] = kdi * (-k[0][1]) % 26;
            ki[1][0] = kdi * (-k[1][0]) % 26;
            d = new int[r][nc];
            d = multiply(r, nc, ki, e);
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < r; j++) {
                    decrypt += alphabet.charAt(d[j][i]);
                }
            if (decrypt.charAt(decrypt.length() - 1) == 'x') {
                int len = decrypt.length();
                char[] temp = decrypt.toCharArray();
                decrypt = "";
                for (int i = 0; i < len - 1; i++)
                    decrypt += temp[i];
            }
            System.out.println("Decrypted text: " + decrypt);
        } else if (r == 3 && c == 3) {
            int nc;
            if (plaintext.length() % 3 == 0) {
                nc = plaintext.length() / 3;
                p = new int[3][nc];
            } else {
                nc = plaintext.length() / 3 + 1;
                p = new int[3][nc];
            }
            // System.out.println(nc);
            int l = 0;
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < r; j++) {
                    // System.out.println("i:"+i+" j:"+j);
                    if (i == nc - 1 && j == r - 1 && ((plaintext.length() % 3 == 2) || (plaintext.length() % 3 == 1)))
                        p[j][i] = alphabet.indexOf('x');
                    else if (i == nc - 1 && j == r - 2 && (plaintext.length() % 3 == 1))
                        p[j][i] = alphabet.indexOf('x');
                    else
                        p[j][i] = alphabet.indexOf(plaintext.charAt(l++));
                    // System.out.print(p[j][i]+" ");
                }
            // System.out.println("\n");
            e = new int[r][nc];
            e = multiply(r, nc, k, p);
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < r; j++) {
                    encrypt += alphabet.charAt(e[j][i]);
                }
            System.out.println("Encrypted text: " + encrypt);
            ki = new int[3][3];
            kdi = inverse(kd);
            // System.out.println("di: "+kdi);
            ki[0][0] = kdi * ((k[1][1] * k[2][2]) - (k[1][2] * k[2][1])) % 26;
            ki[0][1] = kdi * ((k[0][2] * k[2][1]) - (k[0][1] * k[2][2])) % 26;
            ki[0][2] = kdi * ((k[0][1] * k[1][2]) - (k[0][2] * k[1][1])) % 26;
            ki[1][0] = kdi * ((k[1][2] * k[2][0]) - (k[1][0] * k[2][2])) % 26;
            ki[1][1] = kdi * ((k[0][0] * k[2][2]) - (k[0][2] * k[2][0])) % 26;
            ki[1][2] = kdi * ((k[0][2] * k[1][0]) - (k[0][0] * k[1][2])) % 26;
            ki[2][0] = kdi * ((k[1][0] * k[2][1]) - (k[1][1] * k[2][0])) % 26;
            ki[2][1] = kdi * ((k[0][1] * k[2][0]) - (k[0][0] * k[2][1])) % 26;

            ki[2][2] = kdi * ((k[0][0] * k[1][1]) - (k[0][1] * k[1][0])) % 26;
            for (int i = 0; i < 3; i++)
                for (int j = 0; j < 3; j++) {
                    if (ki[i][j] < 0)
                        ki[i][j] = check(ki[i][j]);
                    // System.out.print(ki[i][j]+" ");
                }
            d = new int[r][nc];
            d = multiply(r, nc, ki, e);
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < r; j++) {
                    decrypt += alphabet.charAt(d[j][i]);
                }
            if (decrypt.charAt(decrypt.length() - 1) == 'x') {
                int len = decrypt.length();
                char[] temp = decrypt.toCharArray();
                if (decrypt.charAt(decrypt.length() - 2) == 'x') {
                    decrypt = "";
                    for (int i = 0; i < len - 2; i++)
                        decrypt += temp[i];
                } else {
                    decrypt = "";
                    for (int i = 0; i < len - 1; i++)
                        decrypt += temp[i];
                }
            }
            System.out.println("Decrypted text: " + decrypt);
        }
    }
}

```


# Output:

```shell
Enter the plaintext to be encrypted:
retreatnow
Enter the row and column of key matrix:
3 3
Enter the key matrix:(0-25)
1 0 2
10 20 15
0 1 2
Encrypted text: dpqrqevkpqlr
Decrypted text: retreatnow
```