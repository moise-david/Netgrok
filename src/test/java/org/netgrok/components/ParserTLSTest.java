package org.netgrok.components;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.nio.file.Files;

import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.ByteBufferKaitaiStream;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import org.netgrok.components.network.Pcap;
import org.netgrok.components.network.EthernetFrame;
import org.netgrok.components.network.Ipv4Packet;
import org.netgrok.components.network.Ipv6Packet;
import org.netgrok.components.network.TcpSegment;
import org.netgrok.components.network.UdpDatagram;
import org.netgrok.components.network.TlsClientHello;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Test;
import org.junit.Before;

public class ParserTLSTest {
    Parser parser;
    Pcap[] pcaps;
    File[] filePaths;
    String[] hostNames;
    
    Pcap.Packet[] packets;
    
    int TEST_PACKETS = 2;
    File FILE_PATH_0 = new File("src/test/resources/oneclienthello.pcap");
    String HOST_NAME_0 = "ad.doubleclick.net";
    File FILE_PATH_1 = new File("src/test/resources/Unit_Test_1_Single_Google_Packet.pcap");
    String HOST_NAME_1 = "www.google.com";
    
    String TEST_MESSAGE = "TESTING: Parser.packetHostname() method";
    String LINE_BREAK = "--------------------------------------------------------------------------------";
    
    @Before
    public void setUp() {
        parser = new Parser();
        pcaps = new Pcap[TEST_PACKETS];
        packets = new Pcap.Packet[TEST_PACKETS];
        
        filePaths = new File[TEST_PACKETS];
        hostNames = new String[TEST_PACKETS];
        
        filePaths[0] = FILE_PATH_0;
        hostNames[0] = HOST_NAME_0;
        filePaths[1] = FILE_PATH_1;
        hostNames[1] = HOST_NAME_1;
    }
    
    @Test
    public void test() {
        System.err.println();
        System.err.println(TEST_MESSAGE);
        System.err.println(LINE_BREAK);
        try {
            for (int i = 0; i < TEST_PACKETS; i++) {
                Pcap pcap = parser.pcapFromFile(filePaths[i].toString());
                pcaps[i] = pcap;
                packets[i] = parser.packetFromPcap(pcap, 0);
            }
            
            for (int i = 0; i < TEST_PACKETS; i++) {
                Pcap pcap = pcaps[i];
                Pcap.Packet packet = packets[i];
                
                String trueHostName = hostNames[i];
                String foundHostName = parser.packetHostName(packet, pcap);
                
                System.err.println("true host name:  " + trueHostName);
                System.err.println("found host name: " + foundHostName);
                System.err.println();
            }
        }
        catch (FileNotFoundException ex) {
            System.err.println("EXCEPTION: could not find file");
            System.err.println();
        }
        catch (IOException ex) {
            System.err.println("EXCEPTION: I/O exception");
            System.err.println();
        }
        catch (AssertionError err) {
            System.err.println("FAILURE: host name did not match");
            System.err.println();
        }
        System.err.println(LINE_BREAK);
        System.err.println();
    }
    
    @After
    public void tearDown() {
        // TODO
    }
}
