package org.netgrok.components;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

public class CaptureRunner {

    private final DBManager db;
    private final PacketListener listener;
    private PcapHandle handle;

    public CaptureRunner(CaptureLoader loaded) {
        this.db = new DBManager();
        this.handle = loaded.getHandle();
        this.listener = (Packet packet) -> {
            this.db.packetToDB(packet, this.handle);
        };
    }

    public void start() {
        try {
            this.handle.loop(-1, this.listener);
        } catch (NotOpenException ex) {
            Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PcapNativeException ex) {
            Logger.getLogger(CaptureRunner.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            System.out.println("Closing Netgrok...");
        }
    }

    public void shutdown() {
        try {
            this.handle.breakLoop();
            this.handle.close();
            this.db.close();
        } catch (NotOpenException ex) {
            Logger.getLogger(CaptureRunner.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public DBManager getDatabase(){return db;}
}
