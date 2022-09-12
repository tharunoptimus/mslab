# Code:

```java

import java.util.Scanner;

public class ExtendedEuclidGCD {
    public static void main(String[] args) {
        int quotient, remainderOne, remainderTwo, r, s1, s2, s, t1, t2, t;
        s1 = 1;
        s2 = 0;
        t1 = 0;
        t2 = 1;
        remainderTwo = 1000;
        try (Scanner sc = new Scanner(System.in)) {
            int numberOne = sc.nextInt();
            int numberTwo = sc.nextInt();
            remainderOne = numberOne;
            remainderTwo = numberTwo;
            while (remainderTwo > 0) {
                quotient = remainderOne / remainderTwo;
                r = remainderOne - quotient * remainderTwo;
                remainderOne = remainderTwo;
                remainderTwo = r;
                s = s1 - quotient * s2;
                s1 = s2;
                s2 = s;
                t = t1 - quotient * t2;
                t1 = t2;
                t2 = t;
            }
            int res = numberOne * s1 + numberTwo * t1;
            System.out.println("GCD : " + res);
        }
    }
}


```


# Output:
```shell
95
25
GCD : 5
```