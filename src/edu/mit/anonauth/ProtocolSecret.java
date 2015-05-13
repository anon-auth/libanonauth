package edu.mit.anonauth;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

/*
 * Class to contain protocol secret.  
 */
public class ProtocolSecret {
    private byte[] secretHash;
    private BigInteger challenge;
    private List<SecretBox> secrets;  // List of polynomials.  Index corresponds to poly degree.  
    private HashMap<String, List<Point>> userPoints = new HashMap<String, List<Point>>();  
    // Hashes username to their list of private points/secret shares
    private List<Point> publicPoints;   // current public points, reset w/ revoke.  
    private List<String> blacklist;  // List of usernames revoked.  
    private int polyDegree;  // k = current degree of polynomial
    private static int maxPolyDegree = 2;  // r = max. degree of polynomial
    
    public ProtocolSecret() {
        setUpScheme();
    }
    
    public void setUpScheme() {
        polyDegree = 2;
        // maxPolyDegree = 2;
        secrets = new ArrayList<SecretBox>();
        // One-time run to hardcode the boxes.
        SecretBox rbox = SecretBox.randomSecretBox(1);
        // List<BigInteger> coeffs1 = rbox.getCoefficients(); 
        // System.println(coeffs1);
        List<BigInteger> coeffs1 = new ArrayList<BigInteger>();
        coeffs1.add(BigInteger.valueOf(3));
        coeffs1.add(BigInteger.valueOf(2));
        coeffs1.add(BigInteger.valueOf(1));
        // Secret polynomial is y = x^2 + 2x + 3; secret is 3.
        SecretBox box1 = rbox.fromCoefficients(coeffs1);
        secrets.add(box1);
        secretHash = box1.secretHash();  // Must be 32 bytes
        challenge = BigInteger.valueOf(201);  

        publicPoints = new ArrayList<Point>();
        publicPoints.add(new Point(BigInteger.valueOf(10), BigInteger.valueOf(123)));
        publicPoints.add(new Point(BigInteger.valueOf(1), BigInteger.valueOf(6)));
    }
    
    /* 
    Format of the command:
    1 byte = k (# points)
    y = 16 bytes
    x = 2 bytes
    Hash of secret - 32 bytes
    Challenge - 16 bytes
    */
    public byte[] getBroadcast(){
        byte[] command = new byte[255];
        command[0] = (byte) polyDegree;  // k = 2;
        for (int i = 0; i < polyDegree; i++) {
            // Need k points in command sent.
            Point p = publicPoints.get(i);
            byte[] xBytes = cleanByteArray(p.x, 2);
            byte[] yBytes = cleanByteArray(p.y, 16);
            System.arraycopy(xBytes, 0, command, 1 + i*18, 2);
            System.arraycopy(yBytes, 0, command, 3 + i*18, 16);
        }
        System.arraycopy(secretHash, 0, command, 1 + polyDegree*18, 32);
        System.arraycopy(cleanByteArray(challenge, 16), 0, command, 1 + polyDegree*18 + 32, 16);
        return command;
    }

    /* Returns bigInteger in byte array form of fixed length.  Assumes positive bigInteger */
    public byte[] cleanByteArray(BigInteger bigInteger, int fixedLength) {
        // From http://stackoverflow.com/questions/4407779/biginteger-to-byte
        // If we're only dealing with positive x and y values, 
        // can get rid of leading sign bit to keep array at size 2 and 16 bytes, respectively.  
        byte[] array = bigInteger.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        byte[] fixedArray = new byte[fixedLength];
        System.arraycopy(array, 0, fixedArray, fixedLength - array.length, array.length);
        return fixedArray;
    }
    
    public boolean matchesHMAC(byte[] response) {
        return Arrays.equals(secrets.get(0).hmac(challenge), response);
    }

}
