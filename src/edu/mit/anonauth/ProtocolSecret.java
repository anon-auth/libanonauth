package edu.mit.anonauth;

import java.io.IOException;
import java.lang.Math;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.Collections; 
import java.util.HashMap; 
import java.util.Random;

public class ProtocolSecret {
    private byte[] secretHash;
    private byte[] challenge;
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
        polyDegree = 1;
        // maxPolyDegree = 2;
        secrets = new ArrayList<SecretBox>();
        // One-time run to hardcode the boxes.
        List<BigInteger> coeffs1 = randomSecretBox(1).getCoefficients; 
        System.println(coeffs1);
        SecretBox box1 = fromCoefficients(coeffs1);

        // How do we initialize the secret hash and challenge?  
        secretHash = box1.secretHash();  // Must be 32 bytes
        // challenge = new byte[16];
        challenge = cleanByteArray(new BigInteger(16, rand), 16);
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
        byte[] command = new byte[]{};
        command[0] = (byte) polyDegree;  // k = 1;
        for (int i = 0; i < polyDegree; i++) {
            // Need k points in command.
            Point p = publicPoints.get(i);
            byte[] xBytes = cleanByteArray(p.x, 2);
            byte[] yBytes = cleanByteArray(p.y, 16);
            System.arraycopy(xBytes, 0, command, 1 + i*18, 2);
            System.arraycopy(yBytes, 0, command, 3 + i*18, 16);
        }
        System.arraycopy(secretHash, polyDegree*32, command, 1 + polyDegree*18, 32);
        System.arraycopy(challenge, polyDegree*16, command, 1 + polyDegree*18 + 32, 16);
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
        System.arraycopy(array, 0, fixedArray, fixedLength - array.size(), array.size())
        return fixedArray;
    }
    
    public boolean matchesHMAC(byte[] response) {
        return (box1.hmac(challenge)).equals(response);
    }

}
