package org.netgrok.components;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.Test;
import org.junit.Before;
import org.netgrok.runtime.Netgrok;

public class SinglePacketAgeOffTest {
//
    protected String facebook;
    protected Netgrok ng;
//
    @Before
    public void setUp() {
        facebook = new File("src/test/resources/single_packet_client_hello_facebook.pcap").getAbsolutePath();
        ng = new Netgrok();
        ng.fromFile(facebook);
        ng.setAgeOff(1, "minutes");
        ng.start();
    }
//
//    @Test
//    public void testSetAgeOff() {
//        try {
//            System.out.println("Testing Netgrok's \"setAgeOff\" method.");
//            Network[] networks = ng.getNetworks();
//            assert(networks.length == 1);
//            
//            Thread.sleep(6000);
//            
//            networks = ng.getNetworks();
//            assert(networks.length == 0);
//        } catch (InterruptedException ex) {
//            Logger.getLogger(SinglePacketAgeOffTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }
//
//    @After
//    public void tearDown() {
//        ng.shutdown();
//    }

}
