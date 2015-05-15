package edu.mit.anonauth;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public class SecretBoxTest extends SecretBox {
	
	private static final long serialVersionUID = 1L;
	
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
	
	@Test
	public void testSerialization() throws IOException, ClassNotFoundException {
		SecretBox b1 = randomSecretBox(5);
		
		byte[] enc = serialize(b1);
		SecretBox b2 = (SecretBox) deserialize(enc);
		
		assertEquals(b1.secret(), b2.secret());
		assertTrue(Arrays.equals(b1.secretHash(), b2.secretHash()));
		assertTrue(Arrays.equals(b1.hmac(BigInteger.ZERO), b2.hmac(BigInteger.ZERO)));
	}
    
    private byte[] serialize(Object o) throws IOException {
		// [http://stackoverflow.com/a/8887244]
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		ObjectOutputStream so = new ObjectOutputStream(bo);
		so.writeObject(o);
		so.flush();
		return bo.toByteArray();
    }
    
    private Object deserialize(byte[] enc) throws IOException, ClassNotFoundException {
		ByteArrayInputStream bi = new ByteArrayInputStream(enc);
		ObjectInputStream si = new ObjectInputStream(bi);
		return si.readObject();
    	
    }
}
