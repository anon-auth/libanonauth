package edu.mit.anonauth;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
 * Class to contain protocol secret.  
 */
public class ProtocolSecret {
	
    /**
     * This is k, the current degree of the polynomial. It also matches the
     * number of users who have been revoked.
     */
    private int polyDegree;
    
    /**
     * This is r, the revocation parameter, the maximum number of users who may
     * be revoked. When polyDegree == maxPolyDegree, the system can no longer
     * support revoke().
     */
    private final int maxPolyDegree;
    
    /**
     * A list of the polynomials, in order, which hide the passwords. The i-th
     * polynomial has degree i.
     */
    private final List<SecretBox> secrets; 
    
    /**
     * List of revoked users. Persists across revocations.
     */
    private List<BigInteger> blacklist;
    
    /**
     * The public points for the current polynomial (indexed by polyDegree).
     * When switching to a new polynomial, discard old public points.
     * 
     * Note: public points are sampled from [1, r] and private points are
     * sample from (r, max]. This means that user IDs must be > r.
     */
    private List<Point> publicPoints;
    
    /**
     * The current challenge. This value changes upon each successful
     * authentication attempt.
     */
    private BigInteger challenge;
    
    
    public ProtocolSecret(int r) {
    	polyDegree = -1;	// begins at 0; will increment in advancePolynomial()
    	maxPolyDegree = r;
    	secrets = new ArrayList<SecretBox>();
    	blacklist = new ArrayList<BigInteger>();
    	
    	// Generate all the polynomials!
    	for (int i = 0; i <= maxPolyDegree; i++) {
    		SecretBox box = SecretBox.randomSecretBox(i+1);
    		secrets.add(box);
    	}
    	
    	// Generate public points for the starting polynomial
    	advancePolynomial();
    	
    	// Switch to a new challenge
    	generateChallenge();
    }
    
    /**
     * Get the bytes to be broadcasted by the door. The contents of the
     * advertisement only change when a successful authentication takes place.
     * 
     * Format:
     *   1 byte    k (# points to follow)
     *   
     *   Each Point:
     *     2 bytes   x
     *     16 bytes  y
     *     
     *   32 bytes  hash of secret
     *   16 bytes  challenge
     */
    public byte[] getBroadcast(){
    	int totalLength = 1 + (16 + 2) * publicPoints.size() + 32 + 16;
        byte[] broadcast = new byte[totalLength];
        int i = 0;
        
        // 1 byte - k
        broadcast[i++] = (byte) polyDegree;
        
        // k points
        for (Point p : publicPoints) {
        	insertInteger(broadcast, i, p.x, 2);
        	i = i + 2;
        	insertInteger(broadcast, i, p.y, 16);
        	i = i + 16;
        }
        
        // secret hash
        System.arraycopy(currentSecretBox().secretHash(), 0, broadcast, i, 32);
        i = i + 32;
        
        // challenge
        insertInteger(broadcast, i, challenge, 16);
        i = i + 16;
        
        return broadcast;
    }
    
    /**
     * Parse a card's response, returning true iff the response is valid (i.e.
     * if the door should be opened).
     * 
     * Format:
     *   32 bytes  HMAC
     */
    public boolean checkResponse(byte[] response) {
    	return Arrays.equals(currentSecretBox().hmac(challenge), response);
    }
    
    /**
     * Return a list of a user's r private points. Users are identified by an
     * ID number, which must be > r (maxPolyDegree).
     */
    public List<Point> privatePoints(int user) {
    	if (user <= maxPolyDegree) {
    		throw new ArithmeticException("User ID must be greater than maxPolyDegree");
    	}
    	
    	List<Point> points = new ArrayList<Point>();
    	for (SecretBox box : secrets) {
    		points.add(box.sample(BigInteger.valueOf(user)));
    	}
    	return points;
    }
    
    /**
     * Revoke a user. This action changes the value of the broadcast.
     */
    public void revoke(int user) {
    	if (user <= maxPolyDegree) {
    		throw new ArithmeticException("User ID must be greater than maxPolyDegree");
    	}
    	
    	blacklist.add(BigInteger.valueOf(user));
    	advancePolynomial();
    }
    
    /**
     * Get the current SecretBox, identified by polyDegree.
     */
    protected SecretBox currentSecretBox() {
    	return secrets.get(polyDegree);
    }
    
    /**
     * Switch to the next polynomial/SecretBox, incrementing polyDegree and
     * regenerating all public points.
     */
    protected void advancePolynomial() {
    	// increment index
    	polyDegree = polyDegree + 1;
    	SecretBox box = currentSecretBox();
    	
    	// regenerate public points
    	// ...beginning with revoked users' private points
    	publicPoints = new ArrayList<Point>();
    	for (BigInteger user : blacklist) {
    		Point p = box.sample(user);
    		publicPoints.add(p);
    	}
    	
    	// ...and filling in the rest with x-coordinates from [1, r]
    	int x = 1;
    	while (publicPoints.size() < polyDegree) {
    		Point p = box.sample(BigInteger.valueOf(x));
    		publicPoints.add(p);
    		x++;
    	}
    }
    
    /**
     * Generate a new 128-bit challenge.
     */
    protected void generateChallenge() {
    	challenge = Polynomial.randomBigInteger();
    }
    
    /**
     * Convert a BigInteger to binary and insert it into the given position in
     * an array, right-aligned and padded with zeroes.
     * @param array array to modify
     * @param offset index in array at which to place the integer
     * @param x integer to insert
     * @param len number of bytes to write
     */
    private void insertInteger(byte[] array, int offset, BigInteger x, int len) {
    	if (x.compareTo(BigInteger.ZERO) < 0) {
    		throw new ArithmeticException("insertInteger does not support negative numbers");
    	}
    	
    	byte[] bytes = x.toByteArray();
    	
        // From http://stackoverflow.com/questions/4407779/biginteger-to-byte
        // If we're only dealing with positive x and y values, we can get rid
    	// of leading sign bit to keep array at size 2 and 16 bytes,
    	// respectively.
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }
        
        // Length check!
        if (bytes.length > len) {
			throw new ArithmeticException("x is too long to fit in len bytes");
        }
        
        // Fill in range with leading zeroes
        int numZeroes = len - bytes.length;
        Arrays.fill(array, offset, offset + numZeroes, (byte) 0);
        offset = offset + numZeroes;
        
        // Place integer in remaining spaces
        System.arraycopy(bytes, 0, array, offset, bytes.length);
    }
    
    /**
     * Helper method for ProtocolSecretTest class's constructor.
     * Sets up current polynomial as x^2 + 2x + 3, challenge = 201.
     * Called after super(2).
     */
    protected void setLastPolyForTest() {
        challenge = BigInteger.valueOf(201);
        secrets.remove(2);
        List<BigInteger> coeffs = new ArrayList<BigInteger>();
        coeffs.add(BigInteger.valueOf(3));
        coeffs.add(BigInteger.valueOf(2));
        coeffs.add(BigInteger.valueOf(1));
        secrets.add(SecretBox.fromCoefficients(coeffs));
        advancePolynomial();
        advancePolynomial();
    }
}
