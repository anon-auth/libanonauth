package edu.mit.anonauth;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public class SecretBoxTest extends SecretBox {
	
	public Point sample(BigInteger x) {
		throw new UnsupportedOperationException();
	}
	
	public List<BigInteger> getCoefficients() {
		throw new UnsupportedOperationException();
	}
	
	@Test
	public void test() {
		int r = 5;
		BigInteger c = BigInteger.valueOf(123);
		
		SecretBox a = randomSecretBox(r);
		List<Point> samples = new ArrayList<Point>();
		for (int i = 1; i <= r; i++) {
			samples.add(a.sample(BigInteger.valueOf(i)));
		}
		
		SecretBox b = fromPoints(samples);
		
		assertEquals(a.secret(), b.secret());
		assertTrue(Arrays.equals(a.secretHash(), b.secretHash()));
		assertTrue(Arrays.equals(a.hmac(c), b.hmac(c)));
	}
	
	@Test
	public void testSecretHashLength() {
		SecretBox b = randomSecretBox(5);
		assertEquals(32, b.secretHash().length);
	}
	
	@Test
	public void testHmacLength() {
		SecretBox b = randomSecretBox(5);
		assertEquals(32, b.hmac(BigInteger.ZERO).length);
	}
}
