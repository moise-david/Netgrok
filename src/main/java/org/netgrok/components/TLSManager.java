package org.netgrok.components;

import io.kaitai.struct.ByteBufferKaitaiStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.BufferUnderflowException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.TcpPacket;

public class TLSManager {

    private final HashMap<String, CertStream> certManager = new HashMap<>();
    private final Connection conn;
    private final HashSet<Long> trackingAck = new HashSet<>();
    private final CertificateFactory cf;
    private final PublicSuffix suffix = new PublicSuffix();

    public TLSManager(Connection c) throws CertificateException {
        this.cf = CertificateFactory.getInstance("X.509");
        this.conn = c;
    }
        
    private class CertStream {
        private final HashMap<Long, byte[]> seqPack = new HashMap<>();
        private final TreeSet<Long> keys = new TreeSet<>();
        private int remainingLen;
        private final int firstCertLen;
        private final long ackKey;
        
        private CertStream(int first, long ack){
            this.ackKey = ack;
            this.firstCertLen = first;
            this.remainingLen = first;
        }
        
        private boolean isDone(){ return remainingLen <= 0; }
        
        private void addSeqPack(long cSeq, byte[] segment){
            this.remainingLen -= segment.length;
            keys.add(cSeq);
            seqPack.put(cSeq, segment);
        }
        
        private void generateCertificate(String src){
            ByteArrayOutputStream certsStream = new ByteArrayOutputStream();
            keys.forEach((k) -> {
                try {
                    certsStream.write(seqPack.remove(k));
                } catch (IOException ex) {
                    Logger.getLogger(TLSManager.class.getName()).log(Level.SEVERE, null, ex);
                }
            });
            createCertificate(certsStream.toByteArray(), src);
        }
    }
    
    private class CertInfo {
        private String country = null;
        private String organization = null;
        private String organizationalUnit = null;
        private String stateProvince = null;
        private String commonName = null;
        private String location = null;
        private List<String> domains = new ArrayList<>();
                
        private CertInfo(X509Certificate cert){
            try {
                String[] principal = cert.getSubjectX500Principal().getName().trim().split(",");
                for (String p : principal){
                    String[] field = p.split("=");
                    if ("C".equals(field[0]) && country==null) this.country = field[1];
                    else if ("O".equals(field[0]) && organization==null) {
                        int len = field[1].length();
                        if (field[1].endsWith("\\")) this.organization = field[1].substring(0, len-1);
                        else this.organization = field[1];
                    }
                    else if ("OU".equals(field[0]) && organizationalUnit==null && !field[1].startsWith("Domain Control Validated")) this.organizationalUnit = field[1];
                    else if ("ST".equals(field[0]) && stateProvince==null) this.stateProvince = field[1];
                    else if ("CN".equals(field[0]) && commonName==null) this.commonName = field[1];
                    else if ("L".equals(field[0]) && location==null) this.location = field[1];
                }
                if (cert.getSubjectAlternativeNames() != null)
                    for (List<?> s : cert.getSubjectAlternativeNames()) if (s.get(0).toString().equals("2")) domains.add((String) s.get(1));
            } catch (CertificateParsingException ex) {
            }
        }

        public String getCountry() { return country; }
        public String getOrganization() { return organization; }
        public String getOrganizationalUnit() { return organizationalUnit; }
        public String getStateProvince() { return stateProvince; }
        public String getCommonName() { return commonName; }
        public String getLocation() { return location; }
        public List<String> getDomains() { return domains; }
        
    }

    public void parsePayload(InetAddress src, InetAddress dst, TcpPacket tcp) {
        byte[] payload = tcp.getPayload().getRawData();
        if (payload.length >= 6 && payload[0] == 22){
            int type = payload[5];
            if (type == 1) clientHello(dst, payload);
            else if (type == 2) serverHello(src, payload, tcp);
        }
        
        long cAck = tcp.getHeader().getAcknowledgmentNumberAsLong();
        if (trackingAck.contains(cAck)){
            long cSeq = tcp.getHeader().getSequenceNumberAsLong();
            CertStream c = ((CertStream) certManager.get(src.getHostAddress()));
            if (c != null){
                if (c.isDone()){
                    c.generateCertificate(src.getHostAddress());
                    certManager.remove(src.getHostAddress());
                    trackingAck.remove(cAck);
                }
                else {
                    if (!c.seqPack.containsKey(cSeq) && cAck == c.ackKey) {
                        c.addSeqPack(cSeq, payload);
                    }
                }
            }
        }
    }

    private void clientHello(InetAddress dst, byte[] payload) {
        try {
            TlsParser nf = new TlsParser(new ByteBufferKaitaiStream(payload));
            if (nf.extensions() != null) {
                int length = nf.extensions().extensions().size();
                TlsParser.Sni sni = (TlsParser.Sni) nf.extensions().extensions().get(length - 1).body();
                String serverName = sni.serverNames().get(0).hostName();
                PreparedStatement psmt = this.conn.prepareStatement("UPDATE ExtHosts SET DNSName = ? WHERE IpAddress = ? AND DNSName ISNULL");
                psmt.setString(1, serverName);
                psmt.setString(2, dst.getHostAddress());
                psmt.executeUpdate();
            }
        } catch (SQLException ex) {
            Logger.getLogger(DBManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BufferUnderflowException ex){
        }
    }

    private void serverHello(InetAddress src, byte[] payload, TcpPacket tcp) {
        int helloLength = 9 + calcLength(Arrays.copyOfRange(payload, 6, 9));
        if (payload.length > helloLength + 6 && payload[helloLength] == 22) certificate(src, Arrays.copyOfRange(payload, helloLength, payload.length), tcp);
    }
    
    private void certificate(InetAddress src, byte[] payload, TcpPacket tcp){
        if (payload[5] == 11) {
            int certLen = calcLength(Arrays.copyOfRange(payload, 9, 12));
            if (certLen > 3){
                long curSeq = tcp.getHeader().getSequenceNumberAsLong();
                long groupAck = tcp.getHeader().getAcknowledgmentNumberAsLong();
                trackingAck.add(groupAck);
                int cLen = calcLength(Arrays.copyOfRange(payload, 12, 15));
                CertStream certStream = new CertStream(cLen, groupAck);
                byte[] certPayload = Arrays.copyOfRange(payload, 15, payload.length);
                certStream.addSeqPack(curSeq, certPayload);
                certManager.put(src.getHostAddress(), certStream);
            }
        }
    }
    
    private int calcLength(byte[] lengthArray){
        return ((lengthArray[0] & 0xff) << 16) | ((lengthArray[1] & 0xff) << 8) | (lengthArray[2] & 0xff);
    }

    private void createCertificate(byte[] certPayload, String src) {
        try {
            InputStream certStream = new ByteArrayInputStream(certPayload);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
            CertInfo cInfo = new CertInfo(cert);
            PreparedStatement preparedStatement;
            String orgName = null;
            if (cInfo.getOrganization() != null) orgName = cInfo.getOrganization();
            else if (cInfo.getOrganizationalUnit() != null) orgName = cInfo.getOrganizationalUnit();
            else if (cInfo.getCommonName() != null) orgName = cInfo.getCommonName();
            if (orgName != null){
                preparedStatement = this.conn.prepareStatement("UPDATE ExtHosts SET SSLOrgName = ? WHERE IpAddress = ? AND SSLOrgName IS NULL");
                preparedStatement.setString(1, orgName);
                preparedStatement.setString(2, src);
                preparedStatement.executeUpdate();
                preparedStatement = this.conn.prepareStatement("UPDATE ExtHosts SET SSLOrgName = ? WHERE DNSName = ? AND SSLOrgName IS NULL");
                for (String dns : cInfo.getDomains()){
                    preparedStatement.setString(1, orgName);
                    preparedStatement.setString(2, dns);
                    preparedStatement.executeUpdate();
                }
            }
        } catch (SQLException ex) {
            Logger.getLogger(TLSManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
        }
    }
}
