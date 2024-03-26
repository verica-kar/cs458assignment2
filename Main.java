// Verica Karanakova
// CS 458 Introduction to Information Security
// Assignment 2

package assignment2.cs458assignment2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    static String ciphertext = "";
    static String plaintext = "";
    static boolean cont = true;

    /* MAIN */
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        Scanner sc2 = new Scanner(System.in);
        while(cont){
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
                    "  (3) Simple Transposition\n" + //
                    "  (4) Double Transposition\n" + //
                    "  (5) Vigenere Cipher\n" + //
                    "  (6) AES-128-ECB\n" + //
                    "  (7) AES-128-CBC\n" + //
                    "  (8) DES-ECB\n" + //
                    "  (9) DES-CBC\n" + //
                    "  (10) 3DES-ECB\n" + //
                    "  (11) 3DES-CBC\n");
            
            int selection = sc.nextInt();

            String text, yesOrNo, sKey, sIV;
            int key;

            if(enc){
                System.out.println("Please Enter your plaintext: ");
                text = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine(); 
            } else {
                System.out.println("Please Enter your ciphertext: ");
                text = sc2.nextLine();
                System.out.println("Did you use a default encryption key? Y/N ");
                yesOrNo = sc2.nextLine();
            }
            

            switch (selection) {
                /* SHIFT CIPHER */
                case 1:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key: ");
                            key = sc.nextInt();
                            System.out.println(shiftCipher(text, key));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(shiftCipher(text, 3));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            key = sc.nextInt();
                            System.out.println(shiftCipherDec(text, key));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(shiftCipherDec(text, 3));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* PERMUTATION CIPHER */
                case 2:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (i.e. 54321): ");
                            ArrayList<Integer> pcKey = stringToList(sc2.nextLine());
                            System.out.println(permutationCipher(text, pcKey));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(permutationCipher(text, new ArrayList<Integer>(Arrays.asList(4, 5, 1, 3, 2))));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            ArrayList<Integer> pcKey = stringToList(sc2.nextLine());
                            System.out.println(permutationCipherDec(text, pcKey));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(permutationCipherDec(text, new ArrayList<Integer>(Arrays.asList(4, 5, 1, 3, 2))));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;
            
                /* SIMPLE TRANSPOSITION */
                case 3:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key: ");
                            key = sc.nextInt();
                            System.out.println(simpleTransposition(text, key));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(simpleTransposition(text, 4));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            key = sc.nextInt();
                            System.out.println(simpleTranspositionDec(text, key));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(simpleTranspositionDec(text, 4));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* DOUBLE TRANSPOSITION */
                case 4:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your row key (i.e. for (3,2,1) enter 321): ");
                            ArrayList<Integer> rowKey = stringToList(sc2.nextLine());
                            System.out.println("Please enter your column key (i.e. for (4,2,3,1) enter 4231): ");
                            ArrayList<Integer> colKey = stringToList(sc2.nextLine());
                            System.out.println(doubleTransposition(text, rowKey, colKey));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(doubleTransposition(text, new ArrayList<Integer>(Arrays.asList(3, 2, 1)), new ArrayList<Integer>(Arrays.asList(4, 2, 1, 3))));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the row key you used: ");
                            ArrayList<Integer> rowKey = stringToList(sc2.nextLine());
                            System.out.println("Please enter the column key you used: ");
                            ArrayList<Integer> colKey = stringToList(sc2.nextLine());
                            System.out.println(doubleTranspositionDec(text, rowKey, colKey));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(doubleTranspositionDec(text, new ArrayList<Integer>(Arrays.asList(3, 2, 1)), new ArrayList<Integer>(Arrays.asList(4, 2, 1, 3))));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* VIGENERE CIPHER */
                case 5:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key: ");
                            sKey = sc2.nextLine();
                            System.out.println(vigenereCipher(text, sKey));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(vigenereCipher(text, "VIG"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println(vigenereCipherDec(text, sKey));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(vigenereCipherDec(text, "VIG"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* AES-128-ECB */
                case 6:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 128 bits/16 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println(aes128(text, sKey, null, "AES/ECB/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(aes128(text, "64656661756C7408", null, "AES/ECB/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println(aes128Dec(text, sKey, null, "AES/ECB/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(aes128Dec(text, "64656661756C7408", null, "AES/ECB/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* AES-128-CBC */
                case 7:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 128 bits/16 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println("Please enter your iv (must be 128 bits/16 bytes): ");
                            sIV = sc2.nextLine();
                            System.out.println(aes128(text, sKey, sIV, "AES/CBC/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(aes128(text, "64656661756C7408", "72616E646F6D6976", "AES/CBC/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println("Please enter the iv you used: ");
                            sIV = sc2.nextLine();
                            System.out.println(aes128Dec(text, sKey, sIV, "AES/CBC/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(aes128Dec(text, "64656661756C7408", "72616E646F6D6976", "AES/CBC/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* DES-ECB */
                case 8:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 64 bits/8 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println(des(text, sKey, null, "DES/ECB/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(des(text, "64656661", null, "DES/ECB/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println(desDec(text, sKey, null, "DES/ECB/NoPadding"));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(desDec(text, "64656661", null, "DES/ECB/NoPadding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* DES-CBC */
                case 9:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 64 bits/8 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println("Please enter your iv (must be 64 bits/8 bytes): ");
                            sIV = sc2.nextLine();
                            System.out.println(des(text, sKey, sIV, "DES/CBC/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(des(text, "64656661", "72616E64", "DES/CBC/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println("Please enter the iv you used: ");
                            sIV = sc2.nextLine();
                            System.out.println(desDec(text, sKey, sIV, "DES/CBC/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(desDec(text, "64656661", "72616E64", "DES/CBC/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;
                
                /* 3DES-ECB */
                case 10:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 128 bits/24 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println(des(text, sKey, null, "DESede/ECB/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(des(text, "64656661756C746465666175", null, "DESede/ECB/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println(desDec(text, sKey, null, "DESede/ECB/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(desDec(text, "64656661756C746465666175", null, "DESede/ECB/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
                    break;

                /* 3DES-CBC */
                case 11:
                    if(enc){
                        if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println("Please enter your key (must be 192 bits/24 bytes): ");
                            sKey = sc2.nextLine();
                            System.out.println("Please enter your iv (must be 64 bits/8 bytes): ");
                            sIV = sc2.nextLine();
                            System.out.println(des(text, sKey, sIV, "DESede/CBC/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println(des(text, "64656661756C746465666175", "72616E64", "DESede/CBC/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    } else {
                        if(yesOrNo.toUpperCase().contains("N")){
                            System.out.println("Please enter the key you used: ");
                            sKey = sc2.nextLine();
                            System.out.println("Please enter the iv you used: ");
                            sIV = sc2.nextLine();
                            System.out.println(desDec(text, sKey, sIV, "DESede/CBC/PKCS5Padding"));
                        } else if(yesOrNo.toUpperCase().contains("Y")){
                            System.out.println(desDec(text, "64656661756C746465666175", "72616E64", "DESede/CBC/PKCS5Padding"));
                        } else {
                            System.out.println("incorrect input");
                        }
                    }
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
        /* make pt a multiple of k so the list is full each time */
        if(pt.length() % k.size() != 0){
            for(int i = 0; i < (pt.length() % k.size()); i++){
                pt += " ";
            }
        }

        /* variables */
        int totalSize = pt.length();
        int count = 0; // keep track of how many characters were iterated through

        /* keep looping until all characters in pt have been iterated through */
        while(count < (totalSize - 1)){
            for(int i = 0; i < k.size(); i++){
                ciphertext += pt.charAt(k.get(i) - 1);
                count++;
            }

            pt = pt.substring(k.size());
        }

        return ciphertext;
    }

    /* CASE 3: SIMPLE TRANSPOSITION */
    public static String simpleTransposition(String pt, int k){
        /* make pt a multiple of k^2 so the matrix is full each time */
        if(pt.length() % Math.pow(k, 2) != 0){
            for(int i = 0; i < (pt.length() % Math.pow(k, 2)); i++){
                pt += " ";
            }
        }

        /* variables */
        char[][] matrix = new char[k][k];
        int counter = 1; // keep track of how many characters were iterated through

        /* keep looping until all characters in pt have been iterated through */
        while(counter < pt.length()){
            /* populate the matrix by row */
            for(int i = 0; i < k; i++){
                for(int j = 0; j < k; j++){
                    matrix[i][j] = pt.charAt(counter - 1);
                }
            }

            /* read from the matrix by column */
            for(int i = 0; i < k; i++){
                for(int j = 0; j < k; j++){
                    ciphertext += String.valueOf(matrix[j][i]);
                }
            }

            /* clear out the matrix */
            matrix = new char[k][k];
        }

        return ciphertext;
    }

    /* CASE 4: DOUBLE TRANSPOSITION */
    public static String doubleTransposition(String pt, ArrayList<Integer> row, ArrayList<Integer> col){
        /* make pt a multiple of the amount of positions available in the matrix */
        if(pt.length() % (row.size() * col.size()) != 0){
            for(int i = 0; i < (pt.length() % (row.size() * col.size())); i++){
                pt += " ";
            }
        }

        /* variables */
        char[][] matrix = new char[row.size()][col.size()];
        char[][] transposedMatrix = new char[row.size()][col.size()];
        int counter = 1; // keep track of how many characters were iterated through

        /* keep looping until all characters in pt have been iterated through */
        while(counter < pt.length()){
            /* populate matrix by row*/
            for(int i = 0; i < row.size(); i++){
                for(int j = 0; j < col.size(); j++){
                    matrix[i][j] = pt.charAt(counter - 1);
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

            /* read from matrix by row */
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
        /* variables */
        ArrayList<Character> alphabet = new ArrayList<Character>(Arrays.asList('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'));
        pt = pt.toUpperCase();//.replaceAll("\\s", "");
        int difference = (pt.length() / k.length());
        int extra = (pt.length() % k.length());
        String firstK = k.toUpperCase();

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
            if(pt.charAt(i) == ' '){
                ciphertext += " ";
            } else if(pt.charAt(i) == 'A'){
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
    public static String aes128(String plaintext, String k, String iv, String mode) throws Exception{
        Cipher cipher = Cipher.getInstance(mode);
        
        SecretKeySpec secretKeySpec = new SecretKeySpec(k.getBytes("UTF-8"), "AES");

        if(iv == null){
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        }

        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /* CASE 8, 9, 10, & 11: DES & 3DES */
    public static String des(String plaintext, String k, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey;

        if(mode.contains("DESede")){
            DESedeKeySpec desKeySpec = new DESedeKeySpec(k.getBytes("UTF-8"));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            secretKey = keyFactory.generateSecret(desKeySpec);
        } else {
            DESKeySpec desKeySpec = new DESKeySpec(k.getBytes("UTF-8"));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            secretKey = keyFactory.generateSecret(desKeySpec);
        }

        if(iv == null){
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        }

        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
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
        if(ct.length() % k.size() != 0){
            for(int i = 0; i < (ct.length() % k.size()); i++){
                ct += " ";
            }
        }

        int totalSize = ct.length();
        int count = 1;

        while(count < totalSize){
            for(int i = 0; i < k.size(); i++){
                plaintext += String.valueOf(ct.charAt(k.indexOf(i + 1)));
                count++;
            }

            ct = ct.substring(k.size());
        }

        return plaintext;
    }

    /* CASE 3: SIMPLE TRANSPOSITION */
    public static String simpleTranspositionDec(String ct, int k){
        /* make pt a multiple of k^2 so the matrix is full each time */
        if(ct.length() % Math.pow(k, 2) != 0){
            for(int i = 0; i < (ct.length() % Math.pow(k, 2)); i++){
                ct += " ";
            }
        }

        /* variables */
        char[][] matrix = new char[k][k];
        int counter = 1; // keep track of how many characters were iterated through

        /* keep looping until all characters in pt have been iterated through */
        while(counter < ct.length()){
            /* populate matrix by column */
            for(int j = 0; j < k; j++){
                for(int i = 0; i < k; i++){
                    matrix[i][j] = ct.charAt(counter - 1);
                    counter++;
                }
            }

            /* read from matrix by row */
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
        /* make pt a multiple of the amount of positions available in the matrix */
        if(ct.length() % (row.size() * col.size()) != 0){
            for(int i = 0; i < (ct.length() % (row.size() * col.size())); i++){
                ct += " ";
            }
        }

        char[][] matrix = new char[row.size()][col.size()];
        char[][] transposedMatrix = new char[row.size()][col.size()];
        int counter = 1; // keep track of how many characters were iterated through

        /* keep looping until all characters in pt have been iterated through */
        while(counter < ct.length()){
            /* populate matrix by row */
            for(int i = 0; i < row.size(); i++){
                for(int j = 0; j < col.size(); j++){
                    matrix[i][j] = ct.charAt(counter - 1);
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
            
            /* read from matrix by row */
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
        ct = ct.toUpperCase();//.replaceAll("\\s", "");
        int difference = (ct.length() / k.length());
        int extra = (ct.length() % k.length());
        String firstK = k.toUpperCase();

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
            if(ct.charAt(i) == ' '){
                plaintext += " ";
            } else if(ct.charAt(i) == 'A'){
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

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        if(iv == null){
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        }

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, "UTF-8");
    }

    /* CASE 8, 9, 10, & 11: DES & 3DES */
    public static String desDec(String ciphertext, String k, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey;

        if(mode.contains("DESede")){
            DESedeKeySpec desKeySpec = new DESedeKeySpec(k.getBytes("UTF-8"));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            secretKey = keyFactory.generateSecret(desKeySpec);
        } else {
            DESKeySpec desKeySpec = new DESKeySpec(k.getBytes("UTF-8"));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            secretKey = keyFactory.generateSecret(desKeySpec);
        }

        if(iv == null){
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        }

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, "UTF-8");
    }

/* -------------------------------- HELPER FUNCTIONS -------------------------------- */
    static ArrayList<Integer> stringToList(String list){
        ArrayList<Integer> al = new ArrayList<>();

        for(int i = 0; i < list.length(); i++){
            al.add(Integer.parseInt(String.valueOf(list.charAt(i))));
        }

        return al;
    }
}