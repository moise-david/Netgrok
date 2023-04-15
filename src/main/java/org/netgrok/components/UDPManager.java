package org.netgrok.components;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.UdpPacket;

public class UDPManager {

    private final Connection conn;

    public UDPManager(Connection connection) {
        this.conn = connection;
    }

    public void parseMDNS(InetAddress src, InetAddress dst, UdpPacket udp) {
        try {
            DnsPacket.DnsHeader mdns = DnsPacket.newPacket(udp.getPayload().getRawData(), 0, udp.getPayload().getRawData().length).getHeader();
            if (mdns.isResponse()) {
                mdns.getAnswers().forEach((x) -> {
                    try {
                        String deviceName = x.getName().decompress(mdns.getRawData());
                        String rData = x.getRData().toString();
                        boolean isIPv4 = rData.split("ADDRESS:")[1].indexOf(':') < 0;
                        if (isIPv4) {
                            PreparedStatement psmt = this.conn.prepareStatement("UPDATE IntHosts SET HostName = IFNULL(HostName,?) WHERE IpAddress = ?");
                            psmt.setString(1, deviceName);
                            psmt.setString(2, src.getHostAddress());
                            psmt.executeUpdate();
                        }
                    } catch (IllegalRawDataException ex) {
                        Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (SQLException ex) {
                        Logger.getLogger(UDPManager.class.getName()).log(Level.SEVERE, null, ex);
                    }
                });
            }
        } catch (IllegalRawDataException ex) {
            Logger.getLogger(UDPManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void parseDNS(InetAddress src, InetAddress dst, DnsPacket dnsPacket) {
        DnsPacket.DnsHeader dns = dnsPacket.getHeader();
//        dns.getQuestions().forEach(x -> {
//            String deviceName = x.getQName().getName();
//            System.out.println(deviceName);
//        });
        if (dns.isResponse()) {
            dns.getAnswers().forEach(x -> {
                try {
                    String dnsName = x.getName().decompress(dns.getRawData());
//                    if (isIPv4) {
//                        PreparedStatement psmt = this.conn.prepareStatement("UPDATE IntHosts SET HostName = IFNULL(HostName,?) WHERE IpAddress = ?");
//                        psmt.setString(1, deviceName);
//                        psmt.setString(2, src.getHostAddress());
//                        psmt.executeUpdate();
//                    }
                } catch (IllegalRawDataException ex) {
                    Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
                }
            });
        }
    }
}
