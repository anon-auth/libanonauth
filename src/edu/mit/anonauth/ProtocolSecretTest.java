package edu.mit.anonauth;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public class ProtocolSecretTest extends ProtocolSecret {
	
	public ProtocolSecretTest() {
		super(0);
	}
    
    /*
     * Tests a simple decryption/encryption exchange.
     * getBroadcast() returns the byte array the door broadcasts
     * over NFC, while response returns the byte array the 
     * card sends back.  The final assertTrue is done by the 
     * door, to determine whether or not the authorization was successful.
     */
    @Test
    public void test() {
        byte[] command = getBroadcast();
        byte[] response = parseBroadcast(command);
        assertTrue(matchesHMAC(response));
    }
    
    /* Card's parsing and response protocol. */
    public byte[] parseBroadcast(byte[] broadcast){
     // k |( x | y )*k | hashSecret | challenge (max 255)

        Point[] PRIVATE_POINTS = new Point[3];
        PRIVATE_POINTS[0] = new Point(BigInteger.valueOf(5), BigInteger.valueOf(4));
        PRIVATE_POINTS[1] = new Point(BigInteger.valueOf(5), BigInteger.valueOf(102));
        PRIVATE_POINTS[2] = new Point(BigInteger.valueOf(5), BigInteger.valueOf(38));
                 Byte kByte = broadcast[0];
                 int k = kByte.intValue();
                 List<Point> points = new ArrayList<Point>();
                 byte[] hmac = new byte[]{};

                 int hashBegin = 1 + k * 18;
                 int challengeBegin = hashBegin + 32;

                 byte[] hashedSecret = Arrays.copyOfRange(broadcast, hashBegin, hashBegin + 32); //32 bytes
                 BigInteger challenge = new BigInteger(Arrays.copyOfRange(broadcast, hashBegin + 32, hashBegin + 48)); //16 bytes
                 points.add(PRIVATE_POINTS[k]);

                 for (int i = 0; i < k; i++){
                     int pointStart = 1 + i * 18;
                     BigInteger x = new BigInteger(Arrays.copyOfRange(broadcast, pointStart, pointStart + 2)); //2 bytes
                     BigInteger y = new BigInteger(Arrays.copyOfRange(broadcast, pointStart + 2, pointStart + 18)); //16 bytes
                     Point xy = new Point(x, y);

                     points.add(xy);
                 }

                 SecretBox secretBox = SecretBox.fromPoints(points);
                 
//                 BigInteger secretPassword = CryptoLibrary.Shamir(points);
                 byte[] hashedSecretPassword = secretBox.secretHash();
                 //printByteArray(hashedSecretPassword);
                 //printByteArray(hashedSecret);
                 if (Arrays.equals(hashedSecretPassword, hashedSecret)) {
                     // Not a fake door.
                     hmac = secretBox.hmac(challenge);
                 }

                 return hmac;
         }
    
    public void printByteArray(byte[] array) {
        System.out.println(Arrays.toString(array));
    }
}
