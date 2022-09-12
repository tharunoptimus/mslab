# Code:

```java

import java.util.*;

public class Caesar {
    static String c = "abcdefghijklmnopqrstuvwxyz";
    private static Scanner sc;

    public static void main(String[] args) {
        sc = new Scanner(System.in);
        String plain, cipher, decipher;
        System.out.println("Enter plain text");
        plain = sc.nextLine();
        cipher = "";
        decipher = "";
        plain = plain.toLowerCase();
        for (int i = 0; i < plain.length(); i++) {
            cipher += c.charAt((c.indexOf(plain.charAt(i)) + 3) % 26);
        }
        System.out.println("Cipher Text : " + cipher);
        for (int i = 0; i < cipher.length(); i++) {
            int tmp = c.indexOf(cipher.charAt(i)) - 3;
            if (tmp < 0)
                tmp = 26 + tmp;
            decipher += c.charAt(tmp % 26);
        }
        System.out.println("Decipher Text : " + decipher);
    }
}

```


# Output:

```shell
Enter plain text
mysteries
Cipher Text : pbvwhulhv  
Decipher Text : mysteries
```