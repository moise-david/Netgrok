package org.netgrok.components;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.directory.server.dhcp.DhcpException;
import org.apache.directory.server.dhcp.io.DhcpMessageDecoder;
import org.apache.directory.server.dhcp.messages.DhcpMessage;
import org.apache.directory.server.dhcp.options.DhcpOption;
import org.apache.ibatis.jdbc.ScriptRunner;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;

public class DBManager {

    private Connection connection;
    private TLSManager tlsManager;
    private UDPManager udpManager;
    private HTTPManager httpManager;
    private final MacVendorLookup macVendor = new MacVendorLookup();

    private long time;
    private final String CREATE_DATABASE = "DROP TABLE IF EXISTS SameNetwork;\n"
            + "DROP TABLE IF EXISTS History;\n"
            + "DROP TABLE IF EXISTS ExtHosts;\n"
            + "DROP TABLE IF EXISTS IntHosts;\n"
            + "\n"
            + "CREATE TABLE SameNetwork (\n"
            + "    IpAddress VARCHAR(15) PRIMARY KEY,\n"
            + "    NetworkStatus BIT NOT NULL\n"
            + ");\n"
            + "\n"
            + "CREATE TABLE ExtHosts (\n"
            + "    IpAddress VARCHAR(15) NOT NULL,\n"
            + "    SSLOrgName VARCHAR(30) NULL,\n"
            + "    DNSName VARCHAR(30) NULL,\n"
            + "    HTTPHeader VARCHAR(256) NULL,\n"
            + "    FOREIGN KEY(IpAddress) REFERENCES History(Source),\n"
            + "    FOREIGN KEY(IpAddress) REFERENCES History(Destination)\n"
            + ");\n"
            + "\n"
            + "CREATE TABLE IntHosts (\n"
            + "    IpAddress VARCHAR(15) PRIMARY KEY,\n"
            + "    MacAddress VARCHAR(17) NULL,\n"
            + "    Hostname VARCHAR(30) NULL,\n"
            + "    DeviceManufacturer VARCHAR(50) NULL,\n"
            + "    FOREIGN KEY(IpAddress) REFERENCES History(Source),\n"
            + "    FOREIGN KEY(IpAddress) REFERENCES History(Destination)\n"
            + ");\n"
            + "\n"
            + "CREATE TABLE History (\n"
            + "    Time DATETIME2 NOT NULL,\n"
            + "    Source VARCHAR(15) NOT NULL,\n"
            + "    Destination VARCHAR(15) NOT NULL,\n"
            + "    Kilobytes REAL,\n"
            + "    LastConnection DATETIME2 NOT NULL,\n"
            + "    FOREIGN KEY (Source) REFERENCES ExtHosts(IpAddress),\n"
            + "    FOREIGN KEY (Destination) REFERENCES ExtHosts(IpAddress),\n"
            + "    FOREIGN KEY (Source) REFERENCES IntHosts(IpAddress),\n"
            + "    FOREIGN KEY (Destination) REFERENCES IntHosts(IpAddress),\n"
            + "    PRIMARY KEY (Time, Source, Destination)\n"
            + ");\n"
            + "\n"
            + "CREATE TRIGGER ExtHostInsert AFTER INSERT on SameNetwork WHEN NEW.NetworkStatus = 0\n"
            + "BEGIN INSERT INTO ExtHosts(IpAddress) VALUES(NEW.IpAddress); END;\n"
            + "\n"
            + "CREATE TRIGGER IntHostInsert AFTER INSERT on SameNetwork WHEN NEW.NetworkStatus = 1\n"
            + "BEGIN INSERT INTO IntHosts(IpAddress) VALUES(NEW.IpAddress); END;\n"
            + "\n"
            + "CREATE TRIGGER SameNetworkDelete AFTER DELETE on History\n"
            + "BEGIN DELETE FROM SameNetwork WHERE IpAddress NOT IN (SELECT Source FROM History UNION SELECT Destination FROM History); END;\n"
            + "\n"
            + "CREATE TRIGGER ExtHostDelete AFTER DELETE on History\n"
            + "BEGIN DELETE FROM ExtHosts WHERE IpAddress NOT IN (SELECT Source FROM History UNION SELECT Destination FROM History); END;\n"
            + "\n"
            + "CREATE TRIGGER IntHostDelete AFTER DELETE on History\n"
            + "BEGIN DELETE FROM IntHosts WHERE IpAddress NOT IN (SELECT Source FROM History UNION SELECT Destination FROM History); END;\n";

    public Connection getConnection() {
        return connection;
    }

    public DBManager() {
        this.load();
    }

    private void load() {
        try {
            // create a connection to the database
            String dbPath = "jdbc:sqlite:netgrok.db";
            this.connection = DriverManager.getConnection(dbPath);
            tlsManager = new TLSManager(connection);
            udpManager = new UDPManager(connection);
            httpManager = new HTTPManager(connection);

            System.out.println("Connection to SQLite has been established.");
            PrintStream oldOut = System.out;
            System.setOut(new PrintStream(new OutputStream() { @Override public void write(int b) throws IOException {}}));

            ScriptRunner sr = new ScriptRunner(connection);
            Reader reader = new BufferedReader(new StringReader(CREATE_DATABASE));
            sr.runScript(reader);
            System.setOut(oldOut);
        } catch (SQLException | CertificateException ex) {
            Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void close() {
        try {
            if (this.connection != null) {
                this.connection.close();
            }
        } catch (SQLException ex) {
            System.out.println(ex.getMessage());
        }
    }

    public void packetToDB(Packet p, PcapHandle ph) {
        this.time = ph.getTimestamp().getTime();
        if (p.length() > 0) {
            if (p.contains(IpPacket.class)) {
                IpPacket.IpHeader ip = p.get(IpPacket.class).getHeader();
                EthernetPacket.EthernetHeader eth = p.get(EthernetPacket.class).getHeader();
                InetAddress srcIP = ip.getSrcAddr();
                InetAddress dstIP = ip.getDstAddr();
                MacAddress srcEth = eth.getSrcAddr();
                MacAddress dstEth = eth.getDstAddr();
                if (ip.getVersion() == IpVersion.IPV4) {
                    sameNetwork(srcIP, srcEth);
                    sameNetwork(dstIP, dstEth);
                    addToHistory(this.time, srcIP.getHostAddress(), dstIP.getHostAddress(), p.length());
                }
                if (p.contains(TcpPacket.class)) {
                    TcpPacket tcp = p.get(TcpPacket.class);
                    if ((tcp.getHeader().getDstPort().valueAsInt() == 443 || tcp.getHeader().getSrcPort().valueAsInt() == 443) &&
                        tcp.getPayload() != null && tcp.getPayload().getRawData() != null)
                        tlsManager.parsePayload(srcIP, dstIP, tcp);
                    else if (tcp.getHeader().getDstPort().valueAsInt() == 80 || tcp.getHeader().getSrcPort().valueAsInt() == 80)
                        httpManager.parsePayload(srcIP, dstIP, tcp);
                }
                if (p.contains(UdpPacket.class)) {
                    UdpPacket udp = p.get(UdpPacket.class);
                    try {
                        if (udp.getHeader().getDstPort().valueAsInt() == 5353 || udp.getHeader().getSrcPort().valueAsInt() == 5353)
                            udpManager.parseMDNS(srcIP,dstIP,udp);
                        else if (p.contains(DnsPacket.class)) {
                            DnsPacket dns = p.get(DnsPacket.class);
                            udpManager.parseDNS(srcIP,dstIP,dns);
                        }
                        else if (udp.getHeader().getDstPort().valueAsInt() == 67) {
                            ByteBuffer data = ByteBuffer.wrap(udp.getPayload().getRawData());
                            DhcpMessage mess = (new DhcpMessageDecoder()).decode(data);
                            DhcpOption host = mess.getOptions().get((byte)12);
                            if (host != null){
                                PreparedStatement psmt = this.connection.prepareStatement("UPDATE IntHosts SET HostName = IFNULL(HostName,?) WHERE MacAddress = ?");
                                psmt.setString(1, host.toString().substring(14));
                                psmt.setString(2, mess.getHardwareAddress().getNativeRepresentation());
                                psmt.executeUpdate();
                            }
                        }
                    } catch (DhcpException | IOException | SQLException ex){
                        Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
    }

    public void sameNetwork(InetAddress ip, MacAddress mac) {
        try {
            PreparedStatement psmt = this.connection.prepareStatement("INSERT OR IGNORE INTO SameNetwork VALUES(?,?)");
            psmt.setString(1, ip.getHostAddress());
            psmt.setInt(2, ip.isSiteLocalAddress() ? 1 : 0);
            psmt.executeUpdate();
            
            if (ip.isSiteLocalAddress()){
                PreparedStatement macIns = this.connection.prepareStatement("UPDATE IntHosts SET DeviceManufacturer = IFNULL(DeviceManufacturer,?), MacAddress = IFNULL(MacAddress,?) WHERE IpAddress = ?");
                macIns.setString(1, macVendor.parseMac(mac.toString()));
                macIns.setString(2, mac.toString());
                macIns.setString(3, ip.getHostAddress());
                macIns.executeUpdate();
            }
        } catch (SQLException ex) {
            Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void addToHistory(long t, String src, String dst, int packetLength) {
        try {
            PreparedStatement psmt = this.connection.prepareStatement("REPLACE INTO History VALUES(datetime(?,'unixepoch','localtime'),?,?,?+"
                    + "IFNULL((SELECT Kilobytes FROM History WHERE Time=datetime(?,'unixepoch','localtime') AND Source=? AND Destination=?), 0),datetime(?,'unixepoch','localtime'))");
            psmt.setLong(1, (t / 300000) * 300);
            psmt.setString(2, src);
            psmt.setString(3, dst);
            psmt.setDouble(4, (float) packetLength / 1024);
            psmt.setLong(5, (t / 300000) * 300);
            psmt.setString(6, src);
            psmt.setString(7, dst);
            psmt.setLong(8, (t / 1000));
            psmt.executeUpdate();
        } catch (SQLException ex) {
            Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void certificateManager(byte[] certBytes){
        
    }
}
