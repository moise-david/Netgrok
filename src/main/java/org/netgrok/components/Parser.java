package org.netgrok.components;

import java.io.IOException;

import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.ByteBufferKaitaiStream;
import java.util.ArrayList;

import org.netgrok.components.network.Pcap;
import org.netgrok.components.network.EthernetFrame;
import org.netgrok.components.network.Ipv4Packet;
import org.netgrok.components.network.Ipv6Packet;
import org.netgrok.components.network.TcpSegment;
import org.netgrok.components.network.UdpDatagram;
import org.netgrok.components.network.TlsClientHello;

public class Parser {
    final int TCP_HEADER_LENGTH_BITS = 4;
    final int TCP_BYTES_PER_HEADER_WORD = 4;
    final int TCP_OPTIONS_OFFSET = 20;
    final int TLS_MESSAGE_OFFSET = 9;
    final int TLS_HOST_NAME = 0;
    final int SN_0 = 0;

    public Pcap pcapFromFile(String fileName) throws IOException {
        return Pcap.fromFile(fileName);
    }

    public Pcap.Packet packetFromPcap(Pcap pcap, int index) {
        return pcap.packets().get(index);
    }

    public EthernetFrame frame(Pcap.Packet packet, Pcap pcap) {
        EthernetFrame frame;
        ByteBufferKaitaiStream packetBody;

        packetBody = new ByteBufferKaitaiStream(packet._raw_body());
        frame = new EthernetFrame(packetBody, pcap);

        return frame;
    }

    public EthernetFrame.EtherTypeEnum networkProtocol(EthernetFrame frame) {
        return frame.etherType();
    }

    public Ipv4Packet ipv4Packet(EthernetFrame frame) {
        return new Ipv4Packet(new ByteBufferKaitaiStream(frame._raw_body()));
    }

    public Ipv6Packet ipv6Packet(EthernetFrame frame) {
        return new Ipv6Packet(new ByteBufferKaitaiStream(frame._raw_body()));
    }

    public byte[] ipPacketBody(EthernetFrame frame) {
        byte[] body;
        switch (networkProtocol(frame)) {
            case IPV4: body = ipv4Packet(frame)._raw_body(); break;
            case IPV6: body = ipv6Packet(frame).rest(); break;
            default: body = ipv4Packet(frame)._raw_body(); break;
        }
        return body;
    }

    public long tlpId(EthernetFrame frame) {
        long tlpId;
        switch (networkProtocol(frame)) {
            case IPV4: tlpId = ipv4Packet(frame).protocol().id(); break;
            case IPV6: tlpId = ipv6Packet(frame).nextHeaderType(); break;
            default: tlpId = Ipv4Packet.ProtocolEnum.TCP.id();
        }
        return tlpId;
    }

    public Ipv4Packet.ProtocolEnum tlp(long id) {
        return Ipv4Packet.ProtocolEnum.byId(id);
    }

    public TcpSegment tcpSegment(byte[] ipPacketBody) {
        return new TcpSegment(new ByteBufferKaitaiStream(ipPacketBody));
    }

    public UdpDatagram udpDatagram(byte[] ipPacketBody) {
        return new UdpDatagram(new ByteBufferKaitaiStream(ipPacketBody));
    }

    public byte[] tlpPacketBody(byte[] ipPacketBody, long tlpId) {
        byte[] data;
        switch (tlp(tlpId)) {
            case TCP:
                TcpSegment tcpSegment = tcpSegment(ipPacketBody);
                ByteBufferKaitaiStream stream;

                int headerWords = tcpSegment.b12() >> TCP_HEADER_LENGTH_BITS;
                int headerLength = headerWords * TCP_BYTES_PER_HEADER_WORD;
                int dataOffset = headerLength - TCP_OPTIONS_OFFSET;

                stream = new ByteBufferKaitaiStream(tcpSegment.body());
                stream.readBytes(dataOffset);
                data = stream.readBytesFull();
                
                break;
            case UDP:
                UdpDatagram udpDatagram = udpDatagram(ipPacketBody);
                data = udpDatagram.body();
                break;
            default: data = null;
        }
        return data;
    }

    public TlsClientHello tlsClientHelloMsg(byte[] tlpPacketBody) {
        TlsClientHello message;
        ByteBufferKaitaiStream tlsDataStream;
        byte[] msgData;
        ByteBufferKaitaiStream msgStream;

        tlsDataStream = new ByteBufferKaitaiStream(tlpPacketBody);
        tlsDataStream.readBytes(TLS_MESSAGE_OFFSET);
        msgData = tlsDataStream.readBytesFull();
        msgStream = new ByteBufferKaitaiStream(msgData);
        
        // System.err.println("message as String: " + new String(msgData));
        System.err.println("message as hex: ");
        for (int i = 0; i < msgData.length; i++) {
            System.err.print(String.format("%2x ", msgData[i]));
            if ((i + 1) % 16 == 0) System.err.println();
        }
        System.err.println();
        System.err.println("message length: " + msgData.length);
        System.err.println("message KaitaiStream length: " + msgStream.size());
        
        message = new TlsClientHello(msgStream);

        return message;
    }

    public String tlsHostName(TlsClientHello message) {
        String hostName = null;
        ArrayList<TlsClientHello.Extension> extensions;
        TlsClientHello.Extension extension;
        int extensionType;
        byte[] extensionData;
        ByteBufferKaitaiStream dataStream;
        TlsClientHello.Sni serverNameIndication;
        TlsClientHello.ServerName serverName;
        int serverNameType;

        extensions = message.extensions().extensions();
        int extensionsSize = extensions.size();

        for (int i = 0; i < extensionsSize; i++) {
            extension = extensions.get(i);
            extensionType = extension.type();
            switch (extensionType) {
                case TLS_HOST_NAME: // SERVER NAME
                    extensionData = extension._raw_body();
                    dataStream = new ByteBufferKaitaiStream(extensionData);
                    serverNameIndication = new TlsClientHello.Sni(dataStream);
                    serverName = serverNameIndication.serverNames().get(SN_0);
                    serverNameType = serverName.nameType();
                    switch (serverNameType) {
                        case TLS_HOST_NAME: // HOST NAME
                            hostName = new String(serverName.hostName());
                            break;
                        default: hostName = new String(serverName.hostName());
                    }
                    break;
                default: // TODO
            }
        }

        return hostName;
    }

    public String packetHostName(Pcap.Packet packet, Pcap pcap) {
        EthernetFrame frame;
        KaitaiStruct ipPacket;
        byte[] ipPacketBody;
        long tlpId;
        KaitaiStruct tlpPacket;
        byte[] tlpPacketBody;
        TlsClientHello tlsClientHelloMsg;
        String hostName;

        frame = frame(packet, pcap);
        ipPacketBody = ipPacketBody(frame);
        tlpId = tlpId(frame);
        tlpPacketBody = tlpPacketBody(ipPacketBody, tlpId);
        tlsClientHelloMsg = tlsClientHelloMsg(tlpPacketBody);
        hostName = tlsHostName(tlsClientHelloMsg);

        return hostName;
    }
}
