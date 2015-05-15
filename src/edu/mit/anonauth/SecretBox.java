package edu.mit.anonauth;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public abstract class SecretBox implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	protected static String HASH_DIGEST = "SHA-256";
	protected static String HMAC_DIGEST = "HmacSHA256";
	
	protected static class CoefficientSecretBox extends SecretBox {
		
		private static final long serialVersionUID = 1L;
		
		protected List<BigInteger> coefficients;
		
		public CoefficientSecretBox(List<BigInteger> coefficients) {
			this.coefficients = coefficients;
		}
		
		public Point sample(BigInteger x) {
			BigInteger y = Polynomial.samplePolynomial(coefficients, x);
			return new Point(x, y);
		}
		
		public List<BigInteger> getCoefficients() {
			return coefficients;
		}
	}
	
	protected static class PointSecretBox extends SecretBox {
		
		private static final long serialVersionUID = 1L;
		
		protected List<Point> points;
		
		public PointSecretBox(List<Point> points) {
			this.points = points;
		}
		
		public Point sample(BigInteger x) {
			BigInteger y = Polynomial.interpolate(x, points);
			return new Point(x, y);
		}
		
		public List<BigInteger> getCoefficients() {
			throw new UnsupportedOperationException();
		}
	}
	
	/**
	 * Create a SecretBox based on a random polynomial, with a random secret.
	 * @param k the polynomial size, as the number of samples needed to reconstruct 
	 * @return a SecretBox instance
	 */
	public static SecretBox randomSecretBox(int k) {
		BigInteger secret = Polynomial.randomBigInteger();
		List<BigInteger> coefficients = Polynomial.randomPolynomial(k-1, secret);
		return new CoefficientSecretBox(coefficients);
	}
	
	/**
	 * Create a SecretBox from a list of points.
	 * @param points
	 * @return a SecretBox instance
	 */
	public static SecretBox fromPoints(List<Point> points) {
		return new PointSecretBox(points);
	}
	
	/**
	 * Sample a point from the polynomial.
	 * @param x the x-coefficient at which to sample
	 * @return the sampled Point
	 */
	abstract Point sample(BigInteger x);
	
	/**
	 * Get the SecretBox's secret.
	 * @return
	 */
	public BigInteger secret() {
		return sample(BigInteger.ZERO).y;
	}
	
	/**
	 * Get a hash of the SecretBox's secret.
	 * @return
	 */
	public byte[] secretHash() {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance(HASH_DIGEST);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("???");
		}
		return md.digest(secret().toByteArray()); 
	}
	
	/**
	 * Calculate an HMAC using the secret and a given challenge.
	 * @param challenge
	 * @return
	 */
	public byte[] hmac(BigInteger challenge) {
		// http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/AuthJavaSampleHMACSignature.html
		try {
			SecretKeySpec signingKey = new SecretKeySpec(secret().toByteArray(), HMAC_DIGEST);
			Mac mac = Mac.getInstance(HMAC_DIGEST);
			mac.init(signingKey);
			return mac.doFinal(challenge.toByteArray());
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("???");
		}
	}
	
	// hacks to enable hard-coding of SecretBoxes
	abstract List<BigInteger> getCoefficients();
	public static SecretBox fromCoefficients(List<BigInteger> coefficients) {
		return new CoefficientSecretBox(coefficients);
	}
}
