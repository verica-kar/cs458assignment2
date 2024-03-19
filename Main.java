// Verica Karanakova
// CS 458 Introduction to Information Security
// Assignment 2

package assignment2.cs458assignment2;

import java.util.Scanner;

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
                    key = sc.nextInt();
                    System.out.println(permutationCipher(plaintext, key));
                } else {
                    System.out.println(permutationCipher(plaintext, 45132));
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
                break;

            case 5:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();
                break;

            default:
                break;
        };
    }

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

    public static String permutationCipher(String pt, int k){
        return ciphertext;
    }

    public static String simpleTransposition(String pt, int k){
        String ciphertext = "";
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
        }

        return ciphertext;
    }

    public static String doubleTransposition(String pt, int k){
        return ciphertext;
    }

    public static String vigenereCipher(String pt, int k){
        return ciphertext;
    }

}