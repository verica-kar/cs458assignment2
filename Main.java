// Verica Karanakova
// CS 458 Introduction to Information Security
// Assignment 2

package assignment2.cs458assignment2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.List;
import java.util.Scanner;
import java.lang.Math;

public class Main {

    static String ciphertext = "";
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("Please Select an Encryption Technique (Enter the number):\n" + //
                "  (1) Shift Cipher\n" + //
                "  (2) Permutation Cipher\n" + //
                "  (3) Simple Trnasposition\n" + //
                "  (4) Double Transposition\n" + //
                "  (5) Vigenere Cipher\n" + //
                "  (6) AES-128\n" + //
                "  (7) DES\n" + //
                "  (8) 3DES");
        
        int selection = sc.nextInt();

        Scanner sc2 = new Scanner(System.in);
        String plaintext;
        String yesOrNo;
        int key;
        switch (selection) {
            case 1:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine();

                if(yesOrNo.contains("Y")){
                    System.out.println("Please enter your key: ");
                    key = sc.nextInt();
                    System.out.println(shiftCipher(plaintext, key));
                } else {
                    System.out.println(shiftCipher(plaintext, 3));
                }
                break;

            case 2:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine();

                if(yesOrNo.contains("Y")){
                    System.out.println("Please enter your key by rearraging 12345: ");
                    ArrayList<Integer> pcKey = stringToList(sc2.nextLine());
                    System.out.println(permutationCipher(plaintext, pcKey));
                } else {
                    System.out.println(permutationCipher(plaintext, new ArrayList<Integer>(Arrays.asList(4, 5, 1, 3, 2))));
                }
                break;
        
            case 3:
                System.out.println("Please Enter your plaintext (must be greater than 16 letters): ");
                plaintext = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine();

                if(yesOrNo.contains("Y")){
                    System.out.println("Please enter your key (must be <= 4): ");
                    key = sc.nextInt();
                    System.out.println(simpleTransposition(plaintext, key));
                } else {
                    System.out.println(simpleTransposition(plaintext, 2));
                }
                break;

            case 4:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine();

                if(yesOrNo.contains("Y")){
                    System.out.println("Please enter your row key (i.e. for (3,2,1) enter 321): ");
                    ArrayList<Integer> rowKey = stringToList(sc2.nextLine());
                    System.out.println("Please enter your column key (i.e. for (4,2,3,1) enter 321): ");
                    ArrayList<Integer> colKey = stringToList(sc2.nextLine());
                    System.out.println(doubleTransposition(plaintext, rowKey, colKey));
                } else {
                    System.out.println(doubleTransposition(plaintext, new ArrayList<Integer>(Arrays.asList(3, 2, 1)), new ArrayList<Integer>(Arrays.asList(4, 2, 1, 3))));
                }
                break;

            case 5:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine();

                if(yesOrNo.contains("Y")){
                    System.out.println("Please enter your key: ");
                    String sKey = sc2.nextLine();
                    System.out.println(vigenereCipher(plaintext, sKey));
                } else {
                    System.out.println(vigenereCipher(plaintext, "VIG"));
                }
                break;

            default:
                break;
        };
    }

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

    /* HELPER FUNCTIONS */
    static ArrayList<Integer> stringToList(String list){
        ArrayList<Integer> al = new ArrayList<>();

        for(int i = 0; i < list.length(); i++){
            al.add(Integer.valueOf(list.charAt(i)));
        }

        return al;
    }

}