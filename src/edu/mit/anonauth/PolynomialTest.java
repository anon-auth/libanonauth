package edu.mit.anonauth;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class PolynomialTest extends Polynomial {

	@Test
	public void testPrime() {
		assertEquals(PRIME.bitLength(), 129);
		assertTrue(PRIME.isProbablePrime(1000));
	}
	
	@Test
	public void testRandomBigInteger() {
		int r = 1024;	// the number of times to test the RNG
		BigInteger[] ints = new BigInteger[r];
		for (int i = 0; i < r; i++) {
			ints[i] = randomBigInteger();
			
			// generated numbers should be (mod PRIME)
			assertTrue(ints[i].compareTo(BigInteger.ZERO) >= 0);
			assertTrue(ints[i].compareTo(PRIME) < 0);
			assertTrue(ints[i].bitLength() <= 128);
			
			// generated numbers should probably be distinct
			for (int j = 0; j < i; j++) {
				assertFalse(ints[i].equals(ints[j]));
				assertNotEquals(ints[i], ints[j]);
			}
		}
	}
	
	@Test
	public void testRandomLine() {
		testRandomPolynomialDegree(1);
	}
	
	@Test
	public void testRandomCubic() {
		testRandomPolynomialDegree(3);
	}
	
	@Test
	public void testRandomBigPolynomial() {
		testRandomPolynomialDegree(8302);
	}
	
	private void testRandomPolynomialDegree(int degree) {
		BigInteger intercept = randomBigInteger();
		List<BigInteger> coefficients = randomPolynomial(degree, intercept);
		assertEquals(degree+1, coefficients.size());
		assertEquals(intercept, samplePolynomial(coefficients, BigInteger.ZERO));
	}
	
	@Test
	public void testSampleLine() {
		List<BigInteger> coefficients = new ArrayList<BigInteger>();
		// y = 5x + 0
		coefficients.add(BigInteger.ZERO);
		coefficients.add(BigInteger.valueOf(5));
		
		assertEquals(BigInteger.ZERO, samplePolynomial(coefficients, BigInteger.ZERO));
		assertEquals(BigInteger.valueOf(5), samplePolynomial(coefficients, BigInteger.ONE));
	}
	
	@Test
	public void testSampleModular() {
		List<BigInteger> coefficients = new ArrayList<BigInteger>();
		// y = 1x + 0
		coefficients.add(BigInteger.ZERO);
		coefficients.add(BigInteger.ONE);
		
		BigInteger smallNum = BigInteger.valueOf(15032);
		BigInteger bigNum = PRIME.add(smallNum);
		assertEquals(smallNum, samplePolynomial(coefficients, bigNum));
	}
	
	@Test
	public void testInterpolateSmall() {
		BigInteger intercept = randomBigInteger();
		int r = 5;
		List<Point> samples = generateAndSample(intercept, r);
		assertEquals(intercept, interpolate(BigInteger.ZERO, samples));
	}
	
	@Test
	public void testInterpolateBig() {
		BigInteger intercept = randomBigInteger();
		int r = 500;
		List<Point> samples = generateAndSample(intercept, r);
		assertEquals(intercept, interpolate(BigInteger.ZERO, samples));
	}
	
	private List<Point> generateAndSample(BigInteger intercept, int r) {
		List<BigInteger> coefficients = randomPolynomial(r, intercept);
		List<Point> samples = new ArrayList<Point>();
		for (int i = 1; i <= r+1; i++) {
			BigInteger x = BigInteger.valueOf(i);
			BigInteger y = samplePolynomial(coefficients, x);
			samples.add(new Point(x, y));
		}
		return samples;
	}
}
