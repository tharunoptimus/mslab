# Code:

```java

import java.util.Scanner;

public class Affine {
    static String c = "abcdefghijklmnopqrstuvwxyz";
    private static Scanner sc;

    static int gcd(int a, int b) {
        if (a == 0 || b == 0)
            return 0;
        if (a == b)
            return a;
        if (a > b)
            return gcd(a - b, b);
        return gcd(a, b - a);
    }

    static int invert(int a) {
        int ans = 0;
        for (int j = 0; j < 26; j++) {
            if (a * (j) % 26 == 1) {
                ans = j;
                break;
            }
        }
        return ans;
    }

    public static void main(String[] args) {
        String plain;
        sc = new Scanner(System.in);
        System.out.println("Enter plain text : ");
        plain = sc.nextLine();
        int a = sc.nextInt();
        int b = sc.nextInt();
        int g = gcd(a, b);
        int x = 0;
        if (g != 1) {
            System.out.println("Affine ceaser is not possible");
        } else {
            StringBuilder sb = new StringBuilder();
            StringBuilder sb1 = new StringBuilder();
            for (int i = 0; i < plain.length(); i++) {
                char tmp = plain.charAt(i);
                int y = (a * (c.indexOf(tmp)) + b) % 26;
                sb.append(c.charAt(y));
            }
            System.out.println("Cipher text is : " + sb);
            int inver = invert(a);
            System.out.println("Inverse is : " + inver);
            for (int i = 0; i < sb.length(); i++) {
                char tmp = sb.charAt(i);
                int mid = inver * (c.indexOf(tmp) - b);

                if (mid < 0) {
                    x = 26 + mid;
                } else {
                    x = inver * (c.indexOf(tmp) - b) % 26;
                }
                sb1.append(c.charAt(x));
            }
            System.out.println("Decipher text is : " + sb1);
        }
    }
}

```

# Output:

```shell
Enter plain text :
telemetry
Enter 'a' : 9
Enter 'b' : 4
Cipher text is : tozoiotbm
Inverse is : 3
Decipher text is : telemetry
```