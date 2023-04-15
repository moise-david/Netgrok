package org.netgrok.components;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.TcpPacket;

public class HTTPManager {

    private final Connection conn;
    private final PublicSuffix suffix = new PublicSuffix();
    
    HTTPManager(Connection connection) {
        this.conn = connection;
    }

    void parsePayload(InetAddress src, InetAddress dst, TcpPacket tcp) {
        String line;
        if (tcp.getPayload() != null && tcp.getPayload().length() > 0) {
            InputStream http = new ByteArrayInputStream(tcp.getPayload().getRawData());
            BufferedReader buff = new BufferedReader(new InputStreamReader(http));
            try {
                if ((line = buff.readLine()) != null && line.startsWith("GET")) {
                    while ((line = buff.readLine()) != null && !line.startsWith("Host")){}
                    if (line != null && line.startsWith("Host")) {
                        String newHttp = line.trim().substring(6);
                        PreparedStatement ps = this.conn.prepareStatement("UPDATE ExtHosts SET HTTPHeader = ? WHERE IpAddress = ? AND HTTPHeader ISNULL");
                        ps.setString(1, newHttp);
                        ps.setString(2, dst.getHostAddress());
                        ps.executeUpdate();
                    }
                }
            } catch (IOException | SQLException ex) {
                Logger.getLogger(HTTPManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
}
