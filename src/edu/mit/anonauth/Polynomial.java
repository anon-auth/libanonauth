package edu.mit.anonauth;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * A Shamir secret sharing implementation, ported roughly from:
 * https://github.com/onenameio/secret-sharing
 */
public class Polynomial {
	
	protected static final BigInteger PRIME = BigInteger.valueOf(2).pow(128).add(BigInteger.valueOf(51));
	protected static SecureRandom rng = new SecureRandom();
	
	public static BigInteger randomBigInteger() {
		// http://stackoverflow.com/a/2290089
		BigInteger r;
		do {
		    r = new BigInteger(PRIME.bitLength(), rng);
		} while (r.compareTo(PRIME) >= 0);
		return r;
	}
	
	public static List<BigInteger> randomPolynomial(int degree, BigInteger intercept) {
		if (degree < 0) {
			throw new ArithmeticException("Degree must be a non-negative number.");
		}
		
		List<BigInteger> coefficients = new ArrayList<BigInteger>();
		coefficients.add(intercept);
		for (int i = 0; i < degree; i++) {
			coefficients.add(randomBigInteger());
		}
		
		return coefficients;
	}
	
	public static BigInteger samplePolynomial(List<BigInteger> coefficients, BigInteger x) { 
		BigInteger y = BigInteger.ZERO;
		for (int exp = 0; exp < coefficients.size(); exp++) {
			BigInteger coeff = coefficients.get(exp);
			y = y.add(coeff.multiply(x.pow(exp)));
		}
		return y.mod(PRIME);
	}
	
	public static BigInteger interpolate(BigInteger at, List<Point> points) {
		BigInteger intercept = BigInteger.ZERO;
		for (Point point : points) {
			BigInteger numerator = BigInteger.ONE;
			BigInteger denominator = BigInteger.ONE;
			
			for (Point other : points) {
				if (point == other)
					continue;
				numerator = numerator.multiply(at.subtract(other.x)).mod(PRIME);
				denominator = denominator.multiply(point.x.subtract(other.x)).mod(PRIME);
			}
			
			BigInteger lagrange = numerator.multiply(denominator.modInverse(PRIME));
			intercept = PRIME.add(intercept).add(point.y.multiply(lagrange)).mod(PRIME);
		}
		return intercept;
	}
}
