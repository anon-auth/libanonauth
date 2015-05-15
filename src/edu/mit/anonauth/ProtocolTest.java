package edu.mit.anonauth;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class ProtocolTest {
	
    @Test
    public void testBasicExchange() {
    	int r = 5;
    	int user = 5001;
    	
    	ProtocolDoor door = new ProtocolDoor(r);
    	ProtocolCard card = new ProtocolCard(door.privatePoints(user));
    	assertTrue(exchange(door, card));
    }
    
    @Test
    public void testRevocation() {
    	int r = 5;
    	int user = 5001;
    	
    	ProtocolDoor door = new ProtocolDoor(r);
    	ProtocolCard card = new ProtocolCard(door.privatePoints(user));
    	
    	assertTrue(exchange(door, card));
    	door.revoke(user);
    	assertFalse(exchange(door, card));
    }
    
    @Test
    public void testRevocationMultiUser() {
    	int r = 5;
    	int userA = 5001;
    	int userB = 5002;
    	
    	ProtocolDoor door = new ProtocolDoor(r);
    	ProtocolCard cardA = new ProtocolCard(door.privatePoints(userA));
    	ProtocolCard cardB = new ProtocolCard(door.privatePoints(userB));
    	
    	assertTrue(exchange(door, cardA));
    	assertTrue(exchange(door, cardB));
    	door.revoke(userB);
    	assertTrue(exchange(door, cardA));
    	assertFalse(exchange(door, cardB));
    }
    
    @Test
    public void testMultipleRevocation() {
    	int r = 50;
    	
    	ProtocolDoor door = new ProtocolDoor(r);
    	
    	List<ProtocolCard> cards = new ArrayList<ProtocolCard>();
    	for (int i = 0; i < r; i++) {
    		int user = r + i + 1;
    		cards.add(new ProtocolCard(door.privatePoints(user)));
    	}
    	
    	for (int round = 0; round < r; round++) {
    		for (int i = 0; i < r; i++) {
    			if (i < round) {
    				assertFalse(exchange(door, cards.get(i)));
    			} else {
    				assertTrue(exchange(door, cards.get(i)));
    			}
    		}
			door.revoke(r + round + 1);
    	}
    }
	
	@Test
	public void testSerialization() throws IOException, ClassNotFoundException {
		int r = 50;
    	int userA = 5001;
    	int userB = 5002;
		
		ProtocolDoor door1 = new ProtocolDoor(r);
		ProtocolCard cardA1 = new ProtocolCard(door1.privatePoints(userA));
		ProtocolCard cardB1 = new ProtocolCard(door1.privatePoints(userB));
    	
    	assertTrue(exchange(door1, cardA1));
    	assertTrue(exchange(door1, cardB1));
    	door1.revoke(userB);
		
		byte[] doorEnc = serialize(door1);
		byte[] cardAEnc = serialize(cardA1);
		byte[] cardBEnc = serialize(cardB1);
		
		ProtocolDoor door2 = (ProtocolDoor) deserialize(doorEnc);
		ProtocolCard cardA2 = (ProtocolCard) deserialize(cardAEnc);
		ProtocolCard cardB2 = (ProtocolCard) deserialize(cardBEnc);
    	assertTrue(exchange(door2, cardA2));
    	assertFalse(exchange(door2, cardB2));
	}
    
    private boolean exchange(ProtocolDoor door, ProtocolCard card) {
    	byte[] broadcast = door.getBroadcast();
    	byte[] response;
    	try {
        	response = card.authenticate(broadcast);
    	} catch (ArithmeticException e) {
    		return false;
    	}
    	return door.checkResponse(response);
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
