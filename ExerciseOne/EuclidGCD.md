# Code

```java

import java.util.Scanner;

public class EuclidGCD {
    public static void main(String[] args) {
        int quotient, remainderOne, remainderTwo, remainder = 0;
        try (Scanner sc = new Scanner(System.in)) {
            int numberOne = sc.nextInt();
            int numberTwo = sc.nextInt();
            remainderOne = numberOne;
            remainderTwo = numberTwo;
        }
        int i = 0;
        do {
            if (i != 0) {
                remainderOne = remainderTwo;
                remainderTwo = remainder;
            }
            if (remainderTwo == 0)
                break;
            quotient = remainderOne / remainderTwo;
            remainder = remainderTwo * quotient - remainderOne;
            i++;
        } while (remainderTwo != 0);

        System.out.println("GCD : " + remainderOne);
    }
}


```


# Output:
```shell
45
15
GCD : 15
```