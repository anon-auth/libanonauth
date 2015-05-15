package edu.mit.anonauth;

import java.io.Serializable;
import java.math.BigInteger;

public class Point implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	public final BigInteger x;
	public final BigInteger y;
	
	public Point(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
	}
	
	public String toString() {
		return "Point<" + x.toString() + "," + y.toString() + ">";
	}
}
