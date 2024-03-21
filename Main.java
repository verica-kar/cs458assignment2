// Verica Karanakova
// CS 458 Introduction to Information Security
// Assignment 2

package assignment2.cs458assignment2;

import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.security.Key;
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
import javax.crypto.spec.SecretKeySpec;

public class Main {

    static String ciphertext = "";
    static String plaintext = "";
    static final String CHARSET = "UTF-8";
    static boolean cont = true;

    /* MAIN */
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        Scanner sc2 = new Scanner(System.in);
        while(cont){
            // Scanner sc = new Scanner(System.in);
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
                    "  (9) DES-CBC\n" + //
                    "  (10) 3DES-\n" + //
                    "  (11) 3DES-\n");
            
            int selection = sc.nextInt();

            // Scanner sc2 = new Scanner(System.in);
            String text, yesOrNo, sKey;
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
                        System.out.println("Would you like to enter a key? (Y/N) ");
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
                        System.out.println("Did you use a default encryption key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            ArrayList<Integer> pcKey = stringToList(sc2.nextLine());
                            System.out.println(permutationCipherDec(text, pcKey));
                        } else {
                            System.out.println(permutationCipherDec(text, new ArrayList<Integer>(Arrays.asList(4, 5, 1, 3, 2))));
                        }
                    }
                    break;
            
                /* SIMPLE TRANSPOSITION */
                case 3:
                    if(enc){
                        System.out.println("Please Enter your plaintext (must be greater than 16 letters): ");
                        text = sc2.nextLine();
                        System.out.println("Would you like to enter a key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be <= 4): ");
                            key = sc.nextInt();
                            System.out.println(simpleTransposition(text, key));
                        } else {
                            System.out.println(simpleTransposition(text, 4));
                        }
                    } else {
                        System.out.println("Please Enter your ciphertext: ");
                        text = sc2.nextLine();
                        System.out.println("Did you use a default encryption key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            key = sc.nextInt();
                            System.out.println(simpleTranspositionDec(text, key));
                        } else {
                            System.out.println(simpleTranspositionDec(text, 4));
                        }
                    }
                    break;

                /* DOUBLE TRANSPOSITION */
                case 4:
                    if(enc){
                        System.out.println("Please Enter your plaintext: ");
                        text = sc2.nextLine();
                        System.out.println("Would you like to enter a key? (Y/N) ");
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
                        System.out.println("Did you use a default encryption key? (Y/N) ");
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
                        System.out.println("Would you like to enter a key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key: ");
                            sKey = sc2.nextLine();
                            System.out.println(vigenereCipher(text, sKey));
                        } else {
                            System.out.println(vigenereCipher(text, "VIG"));
                        }
                    } else {
                        System.out.println("Please Enter your ciphertext: ");
                        text = sc2.nextLine();
                        System.out.println("Did you use a default encryption key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
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
                        System.out.println("Would you like to enter a key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 128 bits/16 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println(aes128(text, sKey, null, "AES/ECB/NoPadding"));
                        } else {
                            System.out.println(aes128(text, "1234567890abcdef", null, "AES/ECB/PKCS5Padding"));
                        }
                    } else {
                        System.out.println("Please Enter your ciphertext: ");
                        text = sc2.nextLine();
                        System.out.println("Did you use a default encryption key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println(aes128Dec(text, sKey, null, "AES/ECB/NoPadding"));
                        } else {
                            System.out.println(aes128Dec(text, "1234567890abcdef", null, "AES/ECB/PKCS5Padding"));
                        }
                    }
                    break;

                /* AES-128-CBC */
                case 7:
                    if(enc){
                        System.out.println("Please Enter your plaintext: ");
                        text = sc2.nextLine();
                        System.out.println("Would you like to enter a key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 128 bits/16 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println(aes128(text, sKey, generateIv(16), "AES/CBC/PKCS5Padding"));
                        } else {
                            System.out.println(aes128(text, "1234567890abcdef", generateIv(16), "AES/ECB/PKCS5Padding"));
                        }
                    } else {
                        System.out.println("Please Enter your ciphertext: ");
                        text = sc2.nextLine();
                        System.out.println("Did you use a default encryption key? (Y/N) ");
                        yesOrNo = sc2.nextLine();

                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println(aes128Dec(text, sKey, generateIv(16), "AES/CBC/PKCS5Padding"));
                        } else {
                            System.out.println(aes128Dec(text, "1234567890abcdef", generateIv(16), "AES/CBC/PKCS5Padding"));
                        }
                    }
                    break;

                /* DES-ECB */
                case 8:
                    // if(enc){
                    //     System.out.println("Please Enter your plaintext: ");
                    //     text = sc2.nextLine();
                    //     System.out.println("Would you like to enter a key? (Y/N) ");
                    //     yesOrNo = sc2.nextLine();

                    //     if(yesOrNo.toUpperCase().contains("Y")){
                    //         System.out.println("Please enter your key (must be 64 bits/8 bytes): ");
                    //         sKey = sc2.nextLine();
                    //         System.out.println(des(text, sKey, null, "DES/ECB/NoPadding"));
                    //     } else {
                    //         System.out.println(des(text, "12345678", null, "DES/ECB/NoPadding"));
                    //     }
                    // } else {
                    //     System.out.println("Please Enter your ciphertext: ");
                    //     text = sc2.nextLine();
                    //     System.out.println("Did you use a default encryption key? (Y/N) ");
                    //     yesOrNo = sc2.nextLine();

                    //     if(yesOrNo.toUpperCase().contains("N")){
                    //         System.out.println("Please enter the key you used: ");
                    //         sKey = sc2.nextLine();
                    //         System.out.println(desDec(text, sKey, null, "DES/ECB/NoPadding"));
                    //     } else {
                    //         System.out.println(desDec(text, "12345678", null, "DES/ECB/NoPadding"));
                    //     }
                    // }
                    break;

                /* DES-CBC */
                case 9:
                    // if(enc){
                    //     System.out.println("Please Enter your plaintext: ");
                    //     text = sc2.nextLine();
                    //     System.out.println("Would you like to enter a key? (Y/N) ");
                    //     yesOrNo = sc2.nextLine();

                    //     if(yesOrNo.toUpperCase().contains("Y")){
                    //         System.out.println("Please enter your key (must be 64 bits/8 bytes): ");
                    //         sKey = sc2.nextLine();
                    //         System.out.println(des(text, sKey, generateIv(16), "AES/CBC/PKCS5Padding"));
                    //     } else {
                    //         System.out.println(des(text, "12345678", generateIv(16), "AES/CBC/PKCS5Padding"));
                    //     }
                    // } else {
                    //     System.out.println("Please Enter your ciphertext: ");
                    //     text = sc2.nextLine();
                    //     System.out.println("Did you use a default encryption key? (Y/N) ");
                    //     yesOrNo = sc2.nextLine();

                    //     if(yesOrNo.toUpperCase().contains("N")){
                    //         System.out.println("Please enter the key you used: ");
                    //         sKey = sc2.nextLine();
                    //         System.out.println(desDec(text, sKey, generateIv(16), "AES/CBC/PKCS5Padding"));
                    //     } else {
                    //         System.out.println(desDec(text, "12345678", generateIv(16), "AES/CBC/PKCS5Padding"));
                    //     }
                    // }
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

            System.out.println("Would you like to encrypt/decrypt again? (Y/N)");
            String res = sc2.nextLine();
            if(res.toUpperCase().contains("Y")){
                cont = true;
                ciphertext = "";
                plaintext = "";
                sc.nextLine();
            } else {
                cont = false;
            }
        }

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
        char[] ptext = pt.toCharArray();
        char[] encrypted = new char[pt.length()];
        int count = 1;

        while(count < pt.length()){
            for(int i = 0; i < k.size(); i++){
                encrypted[i] = ptext[k.get(i) - 1];
                count++;
            }

            for(int i = 0; i < k.size(); i++){
                ciphertext += encrypted[i];
                ptext = pt.substring(k.size()).toCharArray();
            }
        }

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
    public static String aes128(String plaintext, String key, String iv, String mode) throws Exception{
        Cipher cipher = Cipher.getInstance(mode);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(CHARSET), "AES");

        if(iv == null){
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(CHARSET));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        }

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /* CASE 8 & 9: DES */
    public static String des(String plaintext, String k, IvParameterSpec iv, String mode) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(k.getBytes(StandardCharsets.UTF_8), "DES");

        Cipher cipher = Cipher.getInstance(mode);
        if(iv == null){
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        }
        byte[] bytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(bytes);
        
        // Cipher cipher = Cipher.getInstance(mode);
        // // DESKeySpec desKeySpec = new DESKeySpec(KEY.getBytes(CHARSET));
        // // SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        // // SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        // cipher.init(Cipher.ENCRYPT_MODE, key);
        // byte[] encrypted = cipher.doFinal(plaintext.getBytes(CHARSET));
        // return Base64.getEncoder().encodeToString(encrypted);
    }

    /* CASE 10 & 11: 3DES */
    public static String threeDes(String plaintext, String k, IvParameterSpec iv, String mode) throws Exception {
        return "";
    }

/* -------------------------------- DECRYPTION -------------------------------- */
    /* CASE 1: SHIFT CIPHER */
    public static String shiftCipherDec(String ct, int k){
        for(int i = 0; i < ct.length(); i++){
            char let = ct.charAt(i);
            if(let == ' '){
                plaintext += " ";
            } else if((let >= 'a') && (let <= 'z')) {
                if((let - k) < 97){
                let -= k;
                let += 26;
            } else {
                let -= k;
            }
            } else if((let >= 'A') && (let <= 'Z')){
                if((let - k) < 65){
                let -= k;
                let += 26;
            } else {
                let -= k;
            }
            } else {
                return("Invalid charaters used.");
            }
            
            plaintext += String.valueOf(let);
        }
           
        return plaintext;
    }

    /* CASE 2: PERMUTATION CIPHER */
    public static String permutationCipherDec(String ct, ArrayList<Integer> k){
        char[] ctext = ct.toCharArray();
        int count = 1;

        while(count < ct.length()){
            for(int i = 0; i < k.size(); i++){
                plaintext += ctext[k.indexOf(i + 1)];
                count++;
            }
            ctext = ct.substring(k.size()).toCharArray();
        }

        return plaintext;
    }

    /* CASE 3: SIMPLE TRANSPOSITION */
    public static String simpleTranspositionDec(String ct, int k){
        char[][] matrix = new char[k][k];
        int counter = 0;

        while(counter < (ct.length() -1)){
            for(int j = 0; j < k; j++){
                for(int i = 0; i < k; i++){
                    matrix[i][j] = ct.charAt(counter);
                    counter++;
                }
            }

            for(int i = 0; i < k; i++){
                for(int j = 0; j < k; j++){
                    plaintext += String.valueOf(matrix[i][j]);
                }
            }

            matrix = new char[k][k];
        }

        return plaintext;
    }

    /* CASE 4: DOUBLE TRANSPOSITION */
    public static String doubleTranspositionDec(String ct, ArrayList<Integer> row, ArrayList<Integer> col){
        char[][] matrix = new char[row.size()][col.size()];
        char[][] transposedMatrix = new char[row.size()][col.size()];
        int counter = 0;

        while(counter < (ct.length() - 1)){
            /* populate matrix */
            for(int i = 0; i < row.size(); i++){
                for(int j = 0; j < col.size(); j++){
                    matrix[i][j] = ct.charAt(counter);
                    counter++;
                }
            }

            /* transpose columns */
            int cSpot;
            for(int j = 0; j < col.size(); j++){
                cSpot = col.indexOf(j + 1);
                for(int i = 0; i < row.size(); i++){
                    transposedMatrix[i][j] = matrix[i][cSpot];
                }
            }

            matrix = transposedMatrix;
            transposedMatrix = new char[row.size()][col.size()];

            /* transpose rows */
            int rSpot;
            for(int i = 0; i < row.size(); i++){
                rSpot = row.indexOf(i + 1);
                for(int j = 0; j < col.size(); j++){
                    transposedMatrix[i][j] = matrix[rSpot][j];
                }
            }
            
            for(int i = 0; i < row.size(); i++){
                for(int j = 0; j < col.size(); j++){
                    plaintext += String.valueOf(transposedMatrix[i][j]);
                }
            }
        }

        return plaintext;
    }

    /* CASE 5: VIGENERE CIPHER */
    public static String vigenereCipherDec(String ct, String k){
        ArrayList<Character> alphabet = new ArrayList<Character>(Arrays.asList('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'));
        ct = ct.toUpperCase().replaceAll("\\s", "");
        int difference = (ct.length() / k.length());
        int extra = (ct.length() % k.length());
        String firstK = k;

        /* repeat key */
        for(int i = 1; i < difference; i++){ 
            k += firstK;
        }

        /* add remaining letters from key if needed */
        for(int i = 0; i < extra; i++){
            k += String.valueOf(k.charAt(i));
        }

        /* perform vigenere cipher decryption */
        for(int i = 0; i < ct.length(); i++){
            if(ct.charAt(i) == 'A'){
                plaintext += String.valueOf(k.charAt(i)); 
            } else if(k.charAt(i) == 'A'){
                plaintext += String.valueOf(ct.charAt(i)); 
            } else {
                int shiftAmt = (26 - (26 - alphabet.indexOf(k.charAt(i))));
                String chara = String.valueOf(ct.charAt(i));
                plaintext = shiftCipherDec(chara, shiftAmt);
            }
        }

        return plaintext;
    }

    /* CASE 6 & 7: AES-128 */
    public static String aes128Dec(String ciphertext, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(CHARSET), "AES");

        if(iv == null){
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(CHARSET));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        }

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, CHARSET);
    }

    /* CASE 8 & 9: DES */
    // public static String desDec(String ciphertext, String k, IvParameterSpec iv, String mode) throws Exception {
    //     SecretKeySpec key = new SecretKeySpec(k.getBytes(StandardCharsets.UTF_8), "DES");
    
    //     Cipher cipher = Cipher.getInstance(mode);

    //     if(iv == null){
    //         cipher.init(Cipher.DECRYPT_MODE, key);
    //     } else {
    //         cipher.init(Cipher.DECRYPT_MODE, key, iv);
    //     }

    //     byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
    //     return new String(bytes);
    // }
    
    // /* CASE 10 & 11: 3DES */
    // public static String threeDesDec(String plaintext, String k, IvParameterSpec iv, String mode) throws Exception {
    //     return "";
    // }

/* -------------------------------- HELPER FUNCTIONS -------------------------------- */
    static ArrayList<Integer> stringToList(String list){
        ArrayList<Integer> al = new ArrayList<>();

        for(int i = 0; i < list.length(); i++){
            al.add(Integer.valueOf(list.charAt(i)));
        }

        return al;
    }

    // public static Key generateKey(String algo, char[] n) throws Exception {
    //     // return new SecretKeySpec(n, algo);

    //     // SecretKeyFactory key = new SecretKeyFactory.getInstance(n);
    //     // KeySpec spec = new PBEKeySpec(n.toCharArray())


    //     KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
    //     keyGenerator.init(n.getBytes(StandardCharsets.UTF_8));
    //     SecretKey key = keyGenerator.generateKey();
    //     return key;
    // }

    public static String generateIv(int bytes) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[bytes];
        secureRandom.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);

        // SecureRandom secureRandom = new SecureRandom();
        // byte[] iv = secureRandom.engineGenerateSeed(bytes);
        // return new IvParameterSpec(iv);

        // byte[] iv = new byte[bytes];
        // new SecureRandom().nextBytes(iv);
        // return new IvParameterSpec(iv);
    }
}