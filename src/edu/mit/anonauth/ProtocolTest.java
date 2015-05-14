package edu.mit.anonauth;

import static org.junit.Assert.*;

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
    
    public boolean exchange(ProtocolDoor door, ProtocolCard card) {
    	byte[] broadcast = door.getBroadcast();
    	byte[] response;
    	try {
        	response = card.authenticate(broadcast);
    	} catch (ArithmeticException e) {
    		return false;
    	}
    	return door.checkResponse(response);
    }
}
