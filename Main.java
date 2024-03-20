// Verica Karanakova
// CS 458 Introduction to Information Security
// Assignment 2

package assignment2.cs458assignment2;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Main {

    static String ciphertext = "";
    static String plaintext = "";
    static final String CHARSET = "UTF-8";

    /* MAIN */
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Would you like to encrypt or decrypt a message (E/D)? ");
        String ans = sc.nextLine();
        boolean enc;

        if(ans.toUpperCase().contains("E")){
            enc = true;
            ans = " an encryption technique ";
        } else {
            enc = false;
            ans = " the decryption technique that was used ";
        }

        System.out.println("Please select" + ans + "(Enter the number):\n" + //
                "  (1) Shift Cipher\n" + //
                "  (2) Permutation Cipher\n" + //
                "  (3) Simple Trnasposition\n" + //
                "  (4) Double Transposition\n" + //
                "  (5) Vigenere Cipher\n" + //
                "  (6) AES-128-ECB\n" + //
                "  (7) AES-128-CBC\n" + //
                "  (8) DES-ECB\n" + //
                "  (9) DES-CBC" + //
                "  (10) 3DES-\n" + //
                "  (11) 3DES-\n");
        
        int selection = sc.nextInt();

        Scanner sc2 = new Scanner(System.in);
        String text, yesOrNo;
        int key;

        // System.out.println("Please Enter your plaintext: ");
        // plaintext = sc2.nextLine();
        // System.out.println("Would you like to enter a key? Y/N ");
        // yesOrNo = sc2.nextLine();

        switch (selection) {
            /* SHIFT CIPHER */
            case 1:
                if(enc){
                    System.out.println("Please Enter your plaintext: ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your key: ");
                        key = sc.nextInt();
                        System.out.println(shiftCipher(text, key));
                    } else {
                        System.out.println(shiftCipher(text, 3));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the key you used: ");
                        key = sc.nextInt();
                        System.out.println(shiftCipherDec(text, key));
                    } else {
                        System.out.println(shiftCipherDec(text, 3));
                    }
                }
                break;

            /* PERMUTATION CIPHER */
            case 2:
                if(enc){
                    System.out.println("Please Enter your plaintext (must be greater than 5 characters): ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your key by rearraging 12345 (i.e. 54321): ");
                        ArrayList<Integer> pcKey = stringToList(sc2.nextLine());
                        System.out.println(permutationCipher(text, pcKey));
                    } else {
                        System.out.println(permutationCipher(text, new ArrayList<Integer>(Arrays.asList(4, 5, 1, 3, 2))));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the key you used: ");
                        ArrayList<Integer> pcKey = stringToList(sc2.nextLine());
                        System.out.println(permutationCipher(text, pcKey));
                    } else {
                        System.out.println(permutationCipher(text, new ArrayList<Integer>(Arrays.asList(4, 5, 1, 3, 2))));
                    }
                }
                break;
        
            /* SIMPLE TRANSPOSITION */
            case 3:
                if(enc){
                    System.out.println("Please Enter your plaintext (must be greater than 16 letters): ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your key (must be <= 4): ");
                        key = sc.nextInt();
                        System.out.println(simpleTransposition(text, key));
                    } else {
                        System.out.println(simpleTransposition(text, 2));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the key you used: ");
                        key = sc.nextInt();
                        System.out.println(simpleTranspositionDec(text, key));
                    } else {
                        System.out.println(simpleTranspositionDec(text, 2));
                    }
                }
                break;

            /* DOUBLE TRANSPOSITION */
            case 4:
                if(enc){
                    System.out.println("Please Enter your plaintext: ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your row key (i.e. for (3,2,1) enter 321): ");
                        ArrayList<Integer> rowKey = stringToList(sc2.nextLine());
                        System.out.println("Please enter your column key (i.e. for (4,2,3,1) enter 321): ");
                        ArrayList<Integer> colKey = stringToList(sc2.nextLine());
                        System.out.println(doubleTransposition(text, rowKey, colKey));
                    } else {
                        System.out.println(doubleTransposition(text, new ArrayList<Integer>(Arrays.asList(3, 2, 1)), new ArrayList<Integer>(Arrays.asList(4, 2, 1, 3))));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the row key you used: ");
                        ArrayList<Integer> rowKey = stringToList(sc2.nextLine());
                        System.out.println("Please enter the column key you used: ");
                        ArrayList<Integer> colKey = stringToList(sc2.nextLine());
                        System.out.println(doubleTranspositionDec(text, rowKey, colKey));
                    } else {
                        System.out.println(doubleTranspositionDec(text, new ArrayList<Integer>(Arrays.asList(3, 2, 1)), new ArrayList<Integer>(Arrays.asList(4, 2, 1, 3))));
                    }
                }
                break;

            /* VIGENERE CIPHER */
            case 5:
                if(enc){
                    System.out.println("Please Enter your plaintext: ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your key: ");
                        String sKey = sc2.nextLine();
                        System.out.println(vigenereCipher(text, sKey));
                    } else {
                        System.out.println(vigenereCipher(text, "VIG"));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the key you used: ");
                        String sKey = sc2.nextLine();
                        System.out.println(vigenereCipherDec(text, sKey));
                    } else {
                        System.out.println(vigenereCipherDec(text, "VIG"));
                    }
                }
                break;

            /* AES-128-ECB */
            case 6:
                if(enc){
                    System.out.println("Please Enter your plaintext: ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your key (must be 128 bits/16 bytes): ");
                        key = sc.nextInt();
                        System.out.println(aes128(text, generateKey("AES", key), null, "AES/ECB/PKCS5Padding"));
                    } else {
                        System.out.println(aes128(text, generateKey("AES", 1234), null, "AES/ECB/PKCS5Padding"));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the key you used: ");
                        key = sc.nextInt();
                        System.out.println(aes128Dec(text, generateKey("AES", key), null, "AES/ECB/PKCS5Padding"));
                    } else {
                        System.out.println(aes128Dec(text, generateKey("AES", 1234), null, "AES/ECB/PKCS5Padding"));
                    }
                }
                break;

            /* AES-128-CBC */
            case 7:
                if(enc){
                    System.out.println("Please Enter your plaintext: ");
                    text = sc2.nextLine();
                    System.out.println("Would you like to enter a key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("Y")){
                        System.out.println("Please enter your key (must be 128 bits/16 bytes): ");
                        key = sc.nextInt();
                        System.out.println(aes128(text, generateKey("AES", key), generateIv(), "AES/CBC/PKCS5Padding"));
                    } else {
                        System.out.println(aes128(text, generateKey("AES", 1234), generateIv(), "AES/CBC/PKCS5Padding"));
                    }
                } else {
                    System.out.println("Please Enter your ciphertext: ");
                    text = sc2.nextLine();
                    System.out.println("Did you use a default encryption key? Y/N ");
                    yesOrNo = sc2.nextLine();

                    if(yesOrNo.toUpperCase().contains("N")){
                        System.out.println("Please enter the key you used: ");
                        key = sc.nextInt();
                        System.out.println(aes128Dec(text, generateKey("AES", key), generateIv(), "AES/CBC/PKCS5Padding"));
                    } else {
                        System.out.println(aes128Dec(text, generateKey("AES", 1234), generateIv(), "AES/CBC/PKCS5Padding"));
                    }
                }
                break;

            /* DES-ECB */
            case 8:
                break;

            /* DES-CBC */
            case 9:
                break;
            
            /* 3DES-ECB */
            case 10:
                break;

            /* 3DES-CBC */
            case 11:
                break;

            default:
                break;
        };

        sc.close();
        sc2.close();
    }

/* -------------------------------- ENCRYPTION -------------------------------- */
    /* CASE 1: SHIFT CIPHER */
    public static String shiftCipher(String pt, int k){
        for(int i = 0; i < pt.length(); i++){
            char let = pt.charAt(i);
            if(let == ' '){
                ciphertext += " ";
            } else if((let >= 'A') && (let <= 'Z')) {
                if((let + k) > 90){
                    let += k;
                    let -= 26;
                } else {
                    let += k;
                }
            } else if((let >= 'a') && (let <= 'z')){
                if((let + k) > 122) {
                    let += k;
                    let -= 26;
                } else {
                    let += k;
                }
            } else {
                return("Invalid charaters used.");
            }
            ciphertext += String.valueOf(let);
        }
        return ciphertext;
    }

    /* CASE 2: PERMUTATION CIPHER */
    public static String permutationCipher(String pt, ArrayList<Integer> k){
        return ciphertext;
    }

    /* CASE 3: SIMPLE TRANSPOSITION */
    public static String simpleTransposition(String pt, int k){
        char[][] matrix = new char[k][k];
        int counter = 0;

        while(counter < (pt.length() - 1)){
            for(int i = 0; i < k; i++){
                for(int j = 0; j < k; j++){
                    matrix[i][j] = pt.charAt(counter);
                    counter++;
                }
            }

            for(int i = 0; i < k; i++){
                for(int j = 0; j < k; j++){
                    ciphertext += String.valueOf(matrix[j][i]);
                }
            }

            matrix = new char[k][k];
        }

        return ciphertext;
    }

    /* CASE 4: DOUBLE TRANSPOSITION */
    public static String doubleTransposition(String pt, ArrayList<Integer> row, ArrayList<Integer> col){
        char[][] matrix = new char[row.size()][col.size()];
        char[][] transposedMatrix = new char[row.size()][col.size()];
        int counter = 0;

        while(counter < (pt.length() - 1)){
            /* populate matrix */
            for(int i = 0; i < row.size(); i++){
                for(int j = 0; j < col.size(); j++){
                    matrix[i][j] = pt.charAt(counter);
                    counter++;
                }
            }

            /* transpose rows */
            int rSpot;
            for(int i = 0; i < row.size(); i++){
                rSpot = row.get(i);
                for(int j = 0; j < col.size(); j++){
                    transposedMatrix[i][j] = matrix[rSpot - 1][j];
                }
            }

            matrix = transposedMatrix;
            transposedMatrix = new char[row.size()][col.size()];

            /* transpose columns */
            int cSpot;
            for(int j = 0; j < col.size(); j++){
                cSpot = col.get(j);
                for(int i = 0; i < row.size(); i++){
                    transposedMatrix[i][j] = matrix[i][cSpot - 1];
                }
            }

            for(int i = 0; i < row.size(); i++){
                for(int j = 0; j < col.size(); j++){
                    ciphertext += String.valueOf(transposedMatrix[i][j]);
                }
            }
        }

        return ciphertext;
    }

    /* CASE 5: VIGENERE CIPHER */
    public static String vigenereCipher(String pt, String k){
        ArrayList<Character> alphabet = new ArrayList<Character>(Arrays.asList('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'));
        pt = pt.toUpperCase().replaceAll("\\s", "");
        int difference = (pt.length() / k.length());
        int extra = (pt.length() % k.length());
        String firstK = k;

        /* repeat key */
        for(int i = 1; i < difference; i++){ 
            k += firstK;
        }

        /* add remaining letters from key if needed */
        for(int i = 0; i < extra; i++){
            k += String.valueOf(k.charAt(i));
        }

        /* perform vigenere cipher */
        for(int i = 0; i < pt.length(); i++){
            if(pt.charAt(i) == 'A'){
                ciphertext += String.valueOf(k.charAt(i)); 
            } else if(k.charAt(i) == 'A'){
                ciphertext += String.valueOf(pt.charAt(i)); 
            } else {
                int shiftAmt = (26 - (26 - alphabet.indexOf(k.charAt(i))));
                String chara = String.valueOf(pt.charAt(i));
                ciphertext = shiftCipher(chara, shiftAmt);
            }
        }

        return ciphertext;
    }

    /* CASE 6 & 7: AES-128 */
    public static String aes128(String plaintext, SecretKey key, IvParameterSpec iv, String mode) throws Exception{
        Cipher cipher = Cipher.getInstance(mode);

        if(iv == null){
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        }
        
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /* CASE 8 & 9: DES */
    public static String encrypt(String plaintext, SecretKey key, IvParameterSpec iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        // DESKeySpec desKeySpec = new DESKeySpec(KEY.getBytes(CHARSET));
        // SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        // SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encrypted);
    }

/* -------------------------------- DECRYPTION -------------------------------- */
    /* CASE 1: SHIFT CIPHER */
    public static String shiftCipherDec(String pt, int k){
        // for(int i = 0; i < pt.length(); i++){
        //     char let = pt.charAt(i);
        //     if(let == ' '){
        //         ciphertext += " ";
        //     } else if((let >= 'A') && (let <= 'Z')) {
        //         if((let + k) > 90){
        //             let += k;
        //             let -= 26;
        //         } else {
        //             let += k;
        //         }
        //     } else if((let >= 'a') && (let <= 'z')){
        //         if((let + k) > 122) {
        //             let += k;
        //             let -= 26;
        //         } else {
        //             let += k;
        //         }
        //     } else {
        //         return("Invalid charaters used.");
        //     }
        //     ciphertext += String.valueOf(let);
        // }
        return ciphertext;
    }

    /* CASE 2: PERMUTATION CIPHER */
    public static String permutationCipherDec(String pt, ArrayList<Integer> k){
        return ciphertext;
    }

    /* CASE 3: SIMPLE TRANSPOSITION */
    public static String simpleTranspositionDec(String pt, int k){
        // char[][] matrix = new char[k][k];
        // int counter = 0;

        // while(counter < (pt.length() - 1)){
        //     for(int i = 0; i < k; i++){
        //         for(int j = 0; j < k; j++){
        //             matrix[i][j] = pt.charAt(counter);
        //             counter++;
        //         }
        //     }

        //     for(int i = 0; i < k; i++){
        //         for(int j = 0; j < k; j++){
        //             ciphertext += String.valueOf(matrix[j][i]);
        //         }
        //     }

        //     matrix = new char[k][k];
        // }

        return ciphertext;
    }

    /* CASE 4: DOUBLE TRANSPOSITION */
    public static String doubleTranspositionDec(String pt, ArrayList<Integer> row, ArrayList<Integer> col){
        // char[][] matrix = new char[row.size()][col.size()];
        // char[][] transposedMatrix = new char[row.size()][col.size()];
        // int counter = 0;

        // while(counter < (pt.length() - 1)){
        //     /* populate matrix */
        //     for(int i = 0; i < row.size(); i++){
        //         for(int j = 0; j < col.size(); j++){
        //             matrix[i][j] = pt.charAt(counter);
        //             counter++;
        //         }
        //     }

        //     /* transpose rows */
        //     int rSpot;
        //     for(int i = 0; i < row.size(); i++){
        //         rSpot = row.get(i);
        //         for(int j = 0; j < col.size(); j++){
        //             transposedMatrix[i][j] = matrix[rSpot - 1][j];
        //         }
        //     }

        //     matrix = transposedMatrix;
        //     transposedMatrix = new char[row.size()][col.size()];

        //     /* transpose columns */
        //     int cSpot;
        //     for(int j = 0; j < col.size(); j++){
        //         cSpot = col.get(j);
        //         for(int i = 0; i < row.size(); i++){
        //             transposedMatrix[i][j] = matrix[i][cSpot - 1];
        //         }
        //     }

        //     for(int i = 0; i < row.size(); i++){
        //         for(int j = 0; j < col.size(); j++){
        //             ciphertext += String.valueOf(transposedMatrix[i][j]);
        //         }
        //     }
        // }

        return ciphertext;
    }

    /* CASE 5: VIGENERE CIPHER */
    public static String vigenereCipherDec(String pt, String k){
        // ArrayList<Character> alphabet = new ArrayList<Character>(Arrays.asList('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'));
        // pt = pt.toUpperCase().replaceAll("\\s", "");
        // int difference = (pt.length() / k.length());
        // int extra = (pt.length() % k.length());
        // String firstK = k;

        // /* repeat key */
        // for(int i = 1; i < difference; i++){ 
        //     k += firstK;
        // }

        // /* add remaining letters from key if needed */
        // for(int i = 0; i < extra; i++){
        //     k += String.valueOf(k.charAt(i));
        // }

        // /* perform vigenere cipher */
        // for(int i = 0; i < pt.length(); i++){
        //     if(pt.charAt(i) == 'A'){
        //         ciphertext += String.valueOf(k.charAt(i)); 
        //     } else if(k.charAt(i) == 'A'){
        //         ciphertext += String.valueOf(pt.charAt(i)); 
        //     } else {
        //         int shiftAmt = (26 - (26 - alphabet.indexOf(k.charAt(i))));
        //         String chara = String.valueOf(pt.charAt(i));
        //         ciphertext = shiftCipher(chara, shiftAmt);
        //     }
        // }

        return ciphertext;
    }

    /* CASE 6 & 7: AES-128 */
    public static String aes128Dec(String ciphertext,  SecretKey key, IvParameterSpec iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);

        if(iv == null){
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        }

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, CHARSET);
    }

/* -------------------------------- HELPER FUNCTIONS -------------------------------- */
    static ArrayList<Integer> stringToList(String list){
        ArrayList<Integer> al = new ArrayList<>();

        for(int i = 0; i < list.length(); i++){
            al.add(Integer.valueOf(list.charAt(i)));
        }

        return al;
    }

    public static SecretKey generateKey(String algo, int n) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}