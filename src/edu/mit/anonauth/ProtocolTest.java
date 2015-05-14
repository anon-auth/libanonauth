package edu.mit.anonauth;

import static org.junit.Assert.*;

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
