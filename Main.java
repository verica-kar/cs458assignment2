// Verica Karanakova
// CS 458 Introduction to Information Security
// Assignment 2

package assignment2;

import java.util.Scanner;

public class Main {
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

            case 2:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();
                System.out.println("Would you like to enter a key? Y/N ");
                yesOrNo = sc2.nextLine();

                if(yesOrNo.contains("Y")){
                    System.out.println("Please enter your key: ");
                    key = sc.nextInt();
                    System.out.println(permutationCipher(plaintext, key));
                } else {
                    System.out.println(permutationCipher(plaintext, 3));
                }
        
            case 3:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();

            case 4:
                System.out.println("Please Enter your plaintext: ");
                plaintext = sc2.nextLine();

            default:
                break;
        };
    }

    public static String shiftCipher(String pt, int k){
        String ct = "";
        return ct;
    }

    public static String permutationCipher(String pt, int k){
        String ct = "";
        return ct;
    }

    public static String simpleTransposition(String pt, int k){
        String ct = "";
        return ct;
    }

    public static String doubleTransposition(String pt, int k){
        String ct = "";
        return ct;
    }

    public static String vigenereCipher(String pt, int k){
        String ct = "";
        return ct;
    }

}