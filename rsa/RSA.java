package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;


public class RSA {
    private final static BigInteger one = new BigInteger("1");
    private final static SecureRandom random = new SecureRandom();

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;

    RSA(int N) {
        BigInteger p = BigInteger.probablePrime(N / 2, random);
        BigInteger q = BigInteger.probablePrime(N / 2, random);
        BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));

        modulus = p.multiply(q);
        publicKey = new BigInteger("65537");
        privateKey = publicKey.modInverse(phi);
    }


    BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }

    BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(privateKey, modulus);
    }

    public String toString() {
        String s = "";
        s += "public  = " + publicKey + "\n";
        s += "private = " + privateKey + "\n";
        s += "modulus = " + modulus;
        return s;
    }

    public static void main(String[] args) {
        int N = Integer.parseInt(args[0]);
        RSA key = new RSA(N);
        System.out.println((key));

        String s = "test";
        byte[] bytes = s.getBytes();
        BigInteger message = new BigInteger(bytes);

        BigInteger encrypt = key.encrypt(message);
        BigInteger decrypt = key.decrypt(encrypt);
        System.out.println("message   = " + message);
        System.out.println("encrypted = " + encrypt);
        System.out.println("decrypted = " + decrypt);

        BigInteger byteVal = new BigInteger("256");
        StringBuilder sb = new StringBuilder();
        while (decrypt.compareTo(BigInteger.ZERO) > 0) {
            sb.append((char)decrypt.mod(byteVal).intValue());
            decrypt = decrypt.divide(byteVal);
        }

        sb.reverse();
        System.out.println(sb.toString());
    }
}
