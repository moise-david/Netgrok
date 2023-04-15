package org.netgrok.components;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

public class PacketParser {

    private final DBManager database;

    public DBManager getDatabase() {
        return database;
    }
    
    public PacketParser(){
        this.database = new DBManager();
    }
    
    public void parse(Packet packet, PcapHandle handle) {
        this.database.packetToDB(packet, handle);
    }

    public void close() {
        this.database.close();
    }
    
}
