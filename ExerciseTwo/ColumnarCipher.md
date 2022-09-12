# Code:

```java

import java.util.*;

public class ColumnarCipher {
    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter the Plain Text ");
        String PT = scan.next();
        PT = PT.replaceAll(" ", "");
        System.out.println("Enter the Keyword with the no of integers ");
        int n = scan.nextInt();
        int k[] = new int[n];
        for (int i = 0; i < n; i++) {
            k[i] = scan.nextInt();
        }
        int l = PT.length();
        if (l % 3 != 0) {
            l = (l / n) + 1;
        } else {
            l = l / n;
        }

        int mat[][] = new int[l][n];
        int p = 0;
        for (int i = 0; i < l; i++) {
            for (int j = 0; j < n; j++) {
                if (p != PT.length()) {
                    mat[i][j] = (PT.charAt(p) - 97);
                } else {
                    mat[i][j] = -2;
                }
                p++;
            }
        }
        for (int a = 0; a < l; a++) {
            for (int j = 0; j < n; j++) {
                System.out.print((char) (mat[a][j] + 97) + " ");
            }
            System.out.println();
        }
        String CT = "";
        int s = 1, i;
        while (s <= n) {
            for (i = 0; i < n; i++) {
                if (k[i] == s) {
                    for (int j = 0; j < l; j++) {
                        CT += (char) (mat[j][i] + 97);
                    }
                }
            }
            s++;
        }
        System.out.println("The Cipher Text is " + CT);

        PT = "";

        for (int a = 0; a < l; a++) {
            for (int j = 0; j < n; j++) {
                char b = (char) (mat[a][j] + 97);
                if (b != '_') {
                    PT += b;
                }
            }
        }
        System.out.println("The Plain Text is " + PT);
    }

}


```

# Output:

```shell

Enter the Plain Text 
attackpostponed
Enter the Keyword with the no of integers 
3
3 1 2
a t t 
a c k 
p o s 
t p o 
n e d 
The Cipher Text is tcopetksodaaptn
The Plain Text is attackpostponed

```