package edu.mit.anonauth;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public class ProtocolSecretTest extends ProtocolSecret {
    
    @Test
    public void test() {
        byte[] command = getBroadcast();
        byte[] response = parseBroadcast(command);
        assertTrue(matchesHMAC(response));
    }
    
    /* Card's parsing and response protocol. */
    public byte[] parseBroadcast(byte[] broadcast){
     // k |( x | y )*k | hashSecret | challenge (max 255)
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

                 if (hashedSecretPassword.equals(hashedSecret)){
     //Not a fake door
                     hmac = secretBox.hmac(challenge);
                 }

                 return hmac;
         }

}
