# Code:

```java
import java.util.Scanner;
public class NormalGCD {

    public static void main(String[] args){
        try (Scanner sc = new Scanner(System.in)) {
            int a=sc.nextInt();
            int b=sc.nextInt();
            int gcd=0;
            for(int i=1;i<=Math.max(a,b);i++){
                if(a%i==0 && b%i==0 ){
                    gcd=i;
                }
            }
            System.out.println(gcd);
        }
        
        
    }
}

```

# Output:
```shell
15
21
3
```