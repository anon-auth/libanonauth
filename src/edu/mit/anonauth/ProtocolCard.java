package edu.mit.anonauth;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ProtocolCard {
	
	/**
	 * A list of the user's private points, one per polynomial.
	 */
	private List<Point> privatePoints;
	
	public ProtocolCard(List<Point> privatePoints) {
		this.privatePoints = privatePoints;
	}
	
	/**
	 * Authenticate to a door.
	 * @param broadcast the door's broadcast message
	 * @return a response message
	 */
	public byte[] authenticate(byte[] broadcast) {
		// parse the broadcast
		int offset = 0;
		
		int k = numericRange(broadcast, offset, 1).intValueExact();
		offset = offset + 1;
		
		List<Point> points = new ArrayList<Point>();
		for (int i = 0; i < k; i++) {
			BigInteger x = numericRange(broadcast, offset, 2);
			offset = offset + 2;
			
			BigInteger y = numericRange(broadcast, offset, 16);
			offset = offset + 16;
			
			Point pub = new Point(x, y);
			points.add(pub);
		}
		
		byte[] secretHash = Arrays.copyOfRange(broadcast, offset, offset + 32);
		offset = offset + 32;
		
		BigInteger challenge = numericRange(broadcast, offset, 16);
		
		// perform the computation
		Point priv = privatePoints.get(k);
		points.add(priv);
		
		SecretBox box = SecretBox.fromPoints(points);
		
		if (!Arrays.equals(secretHash, box.secretHash())) {
			throw new BroadcastMismatchException("Incorrect secret hash");
		}
		
		return box.hmac(challenge);
	}
	
	/**
	 * Parses a portion of a byte array, turning it from an unsigned sequence
	 * of bytes into an BigInteger.
	 */
	protected BigInteger numericRange(byte[] array, int offset, int len) {
		byte[] bytes = Arrays.copyOfRange(array, offset, offset + len);
		return new BigInteger(1, bytes);
	}
	
	@SuppressWarnings("serial")
	class BroadcastMismatchException extends RuntimeException {
		public BroadcastMismatchException() { }
		public BroadcastMismatchException(String message) { super(message); }
	}
}
