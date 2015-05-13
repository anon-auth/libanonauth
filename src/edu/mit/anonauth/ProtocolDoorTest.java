package edu.mit.anonauth;

import static org.junit.Assert.*;

import org.junit.Test;

public class ProtocolDoorTest extends ProtocolDoor {
	
	public ProtocolDoorTest() { super(2); }
	
    @Test
    public void testBasicExchange() {
    	int r = 5;
    	int user = 101;
    	
    	ProtocolDoor door = new ProtocolDoor(r);
    	ProtocolCard card = new ProtocolCard(door.privatePoints(user));
    	
    	byte[] broadcast = door.getBroadcast();
    	byte[] response = card.authenticate(broadcast);
    	assertTrue(door.checkResponse(response));
    }
}
