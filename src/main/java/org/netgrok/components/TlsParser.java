package org.netgrok.components;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;

public class TlsParser extends KaitaiStruct {
    public static TlsParser fromFile(String fileName) throws IOException {
        return new TlsParser(new ByteBufferKaitaiStream(fileName));
    }

    public TlsParser(KaitaiStream _io) {
        this(_io, null, null);
    }

    public TlsParser(KaitaiStream _io, KaitaiStruct _parent) {
        this(_io, _parent, null);
    }

    public TlsParser(KaitaiStream _io, KaitaiStruct _parent, TlsParser _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }
    private void _read() {
        this.recordLayerHeader = new RecordLayerHeader(this._io, this, _root);
        this.handshakeProtocol = new HandshakeProtocol(this._io, this, _root);
        if (_io().isEof() == false) {
            this.extensions = new Extensions(this._io, this, _root);
        }
    }
    public static class ServerName extends KaitaiStruct {
        public static ServerName fromFile(String fileName) throws IOException {
            return new ServerName(new ByteBufferKaitaiStream(fileName));
        }

        public ServerName(KaitaiStream _io) {
            this(_io, null, null);
        }

        public ServerName(KaitaiStream _io, TlsParser.Sni _parent) {
            this(_io, _parent, null);
        }

        public ServerName(KaitaiStream _io, TlsParser.Sni _parent, TlsParser _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.nameType = this._io.readU1();
            this.length = this._io.readU2be();
            this.hostName = new String(this._io.readBytes(length()), Charset.forName("ASCII"));
        }
        private int nameType;
        private int length;
        private String hostName;
        private TlsParser _root;
        private TlsParser.Sni _parent;
        public int nameType() { return nameType; }
        public int length() { return length; }
        public String hostName() { return hostName; }
        public TlsParser _root() { return _root; }
        public TlsParser.Sni _parent() { return _parent; }
    }
    public static class HandshakeProtocol extends KaitaiStruct {
        public static HandshakeProtocol fromFile(String fileName) throws IOException {
            return new HandshakeProtocol(new ByteBufferKaitaiStream(fileName));
        }

        public HandshakeProtocol(KaitaiStream _io) {
            this(_io, null, null);
        }

        public HandshakeProtocol(KaitaiStream _io, TlsParser _parent) {
            this(_io, _parent, null);
        }

        public HandshakeProtocol(KaitaiStream _io, TlsParser _parent, TlsParser _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.handshakeType = this._io.readU1();
            this.handshakeLength = this._io.readBitsInt(24);
            this._io.alignToByte();
            this.handshakeVersion = this._io.readU2be();
            this.time = this._io.readU4be();
            this.random = this._io.readBytes(28);
            this.sessionIdLength = this._io.readU1();
            this.sessionId = this._io.readBytes(sessionIdLength());
            this.cipherSuitesLength = this._io.readU2be();
            cipherSuites = new ArrayList<Integer>((int) ((cipherSuitesLength() / 2)));
            for (int i = 0; i < (cipherSuitesLength() / 2); i++) {
                this.cipherSuites.add(this._io.readU2be());
            }
            this.compressionMethodsLength = this._io.readU1();
            compressionMetods = new ArrayList<Integer>((int) (compressionMethodsLength()));
            for (int i = 0; i < compressionMethodsLength(); i++) {
                this.compressionMetods.add(this._io.readU1());
            }
        }
        private int handshakeType;
        private long handshakeLength;
        private int handshakeVersion;
        private long time;
        private byte[] random;
        private int sessionIdLength;
        private byte[] sessionId;
        private int cipherSuitesLength;
        private ArrayList<Integer> cipherSuites;
        private int compressionMethodsLength;
        private ArrayList<Integer> compressionMetods;
        private TlsParser _root;
        private TlsParser _parent;
        public int handshakeType() { return handshakeType; }
        public long handshakeLength() { return handshakeLength; }
        public int handshakeVersion() { return handshakeVersion; }
        public long time() { return time; }
        public byte[] random() { return random; }
        public int sessionIdLength() { return sessionIdLength; }
        public byte[] sessionId() { return sessionId; }
        public int cipherSuitesLength() { return cipherSuitesLength; }
        public ArrayList<Integer> cipherSuites() { return cipherSuites; }
        public int compressionMethodsLength() { return compressionMethodsLength; }
        public ArrayList<Integer> compressionMetods() { return compressionMetods; }
        public TlsParser _root() { return _root; }
        public TlsParser _parent() { return _parent; }
    }
    public static class Sni extends KaitaiStruct {
        public static Sni fromFile(String fileName) throws IOException {
            return new Sni(new ByteBufferKaitaiStream(fileName));
        }

        public Sni(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Sni(KaitaiStream _io, TlsParser.Extension _parent) {
            this(_io, _parent, null);
        }

        public Sni(KaitaiStream _io, TlsParser.Extension _parent, TlsParser _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.listLength = this._io.readU2be();
            this.serverNames = new ArrayList<ServerName>();
            {
                int i = 0;
                while (!this._io.isEof()) {
                    this.serverNames.add(new ServerName(this._io, this, _root));
                    i++;
                }
            }
        }
        private int listLength;
        private ArrayList<ServerName> serverNames;
        private TlsParser _root;
        private TlsParser.Extension _parent;
        public int listLength() { return listLength; }
        public ArrayList<ServerName> serverNames() { return serverNames; }
        public TlsParser _root() { return _root; }
        public TlsParser.Extension _parent() { return _parent; }
    }
    public static class Extensions extends KaitaiStruct {
        public static Extensions fromFile(String fileName) throws IOException {
            return new Extensions(new ByteBufferKaitaiStream(fileName));
        }

        public Extensions(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Extensions(KaitaiStream _io, TlsParser _parent) {
            this(_io, _parent, null);
        }

        public Extensions(KaitaiStream _io, TlsParser _parent, TlsParser _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.extensionsLength = this._io.readU2be();
            this.extensions = new ArrayList<Extension>();
            {
                Extension _it;
                int i = 0;
                do {
                    _it = new Extension(this._io, this, _root);
                    this.extensions.add(_it);
                    i++;
                } while (!(_it.type() == 0));
            }
        }
        private int extensionsLength;
        private ArrayList<Extension> extensions;
        private TlsParser _root;
        private TlsParser _parent;
        public int extensionsLength() { return extensionsLength; }
        public ArrayList<Extension> extensions() { return extensions; }
        public TlsParser _root() { return _root; }
        public TlsParser _parent() { return _parent; }
    }
    public static class RecordLayerHeader extends KaitaiStruct {
        public static RecordLayerHeader fromFile(String fileName) throws IOException {
            return new RecordLayerHeader(new ByteBufferKaitaiStream(fileName));
        }

        public RecordLayerHeader(KaitaiStream _io) {
            this(_io, null, null);
        }

        public RecordLayerHeader(KaitaiStream _io, TlsParser _parent) {
            this(_io, _parent, null);
        }

        public RecordLayerHeader(KaitaiStream _io, TlsParser _parent, TlsParser _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.contentType = this._io.ensureFixedContents(new byte[] { 22 });
            this.version = this._io.readU2be();
            this.recordLength = this._io.readU2be();
        }
        private byte[] contentType;
        private int version;
        private int recordLength;
        private TlsParser _root;
        private TlsParser _parent;
        public byte[] contentType() { return contentType; }
        public int version() { return version; }
        public int recordLength() { return recordLength; }
        public TlsParser _root() { return _root; }
        public TlsParser _parent() { return _parent; }
    }
    public static class Extension extends KaitaiStruct {
        public static Extension fromFile(String fileName) throws IOException {
            return new Extension(new ByteBufferKaitaiStream(fileName));
        }

        public Extension(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Extension(KaitaiStream _io, TlsParser.Extensions _parent) {
            this(_io, _parent, null);
        }

        public Extension(KaitaiStream _io, TlsParser.Extensions _parent, TlsParser _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.type = this._io.readU2be();
            this.len = this._io.readU2be();
            switch (type()) {
            case 0: {
                this._raw_body = this._io.readBytes(len());
                KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                this.body = new Sni(_io__raw_body, this, _root);
                break;
            }
            default: {
                this.body = this._io.readBytes(len());
                break;
            }
            }
        }
        private int type;
        private int len;
        private Object body;
        private TlsParser _root;
        private TlsParser.Extensions _parent;
        private byte[] _raw_body;
        public int type() { return type; }
        public int len() { return len; }
        public Object body() { return body; }
        public TlsParser _root() { return _root; }
        public TlsParser.Extensions _parent() { return _parent; }
        public byte[] _raw_body() { return _raw_body; }
    }
    private RecordLayerHeader recordLayerHeader;
    private HandshakeProtocol handshakeProtocol;
    private Extensions extensions;
    private TlsParser _root;
    private KaitaiStruct _parent;
    public RecordLayerHeader recordLayerHeader() { return recordLayerHeader; }
    public HandshakeProtocol handshakeProtocol() { return handshakeProtocol; }
    public Extensions extensions() { return extensions; }
    public TlsParser _root() { return _root; }
    public KaitaiStruct _parent() { return _parent; }
}