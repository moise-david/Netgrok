package org.netgrok.components;

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.TreeSet;

public class Networks {

    private final HashMap<KnownID, HashMap<String, NetworkInfo>> ns = new HashMap();
    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final PublicSuffix suffix = new PublicSuffix();
    
    public Networks() {
        for (KnownID k : KnownID.values()) ns.put(k, new HashMap<>());
    }
    
    public enum KnownID { IP, HTTP, DNS, SSL }
    public SimpleDateFormat getFormat() { return format; }
    
    public void addNetwork(String ip, String http, String dns, String ssl, double upload, double download, long lastC){
//        if (ssl != null) update(ns.get(KnownID.SSL), ssl, ip, upload, download, lastC);
        if (dns != null) update(ns.get(KnownID.DNS), dns, ip, upload, download, lastC);
        else if (http != null) update(ns.get(KnownID.HTTP), http, ip, upload, download, lastC);
        else update(ns.get(KnownID.IP), ip, ip, upload, download, lastC);
    }
    
    private void update(HashMap<String, NetworkInfo> category, String title, String ip, double upload, double download, long lastConn){
        if (category.containsKey(title)) category.get(title).update(ip, upload, download, lastConn);
        else {
            NetworkInfo n = new NetworkInfo();
            n.update(ip, upload, download, lastConn);
            category.put(title, n);
        }
    }
    
    public HashMap getTypeData(KnownID k){ return ns.get(k); }
    
    public String printSimple(){
        System.out.println();
        String printing = "";
        String next;
        for (KnownID k : KnownID.values()){
            if (k != KnownID.IP) {
                HashMap<String, NetworkInfo> groups = ns.get(k);
                if (!groups.keySet().isEmpty()) {
                    switch (k) {
                        case SSL:
                            printing += "Organizations our network connected to:\n";
                            break;
                        case DNS:
                            printing += "Name Servers our network connected to:\n";
                            break;
                        case HTTP:
                            printing += "Unsecured websites our network connected to:\n";
                            break;
                        default:
                            break;
                    }
                    TreeSet<String> ordered = new TreeSet();
                    for (String typeID : groups.keySet()){
                        if((next = suffix.parseDomain(typeID)) != null) ordered.add(next);
                    }
                    for (String o : ordered) printing += String.format("\t%s\n", o);
                    printing += "\n";
                }
            }
        }
        return printing;
    }
    
    public void printDetailed(){
        for (KnownID k : KnownID.values()){
            HashMap<String, NetworkInfo> groups = ns.get(k);
            switch (k) {
                case SSL:
                    System.out.println("Printing all values with known SSL Organization Name:");
                    break;
                case DNS:
                    System.out.println("Printing all values with known Name Server:");
                    break;
                case HTTP:
                    System.out.println("Printing all values with known HTTP Header Name:");
                    break;
                default:
                    System.out.println("Printing all other values using IPs as indicators:");
                    break;
            }
            String printing = "";
            for (String typeID : groups.keySet()){
                NetworkInfo nInfo = groups.get(typeID);
                printing += String.format("\tGroup Name: %s\n"
                        + "\t\tLast Connection: %s\n"
                        + "\t\tUpload (in KB): %s\n"
                        + "\t\tDownload (in KB): %s\n"
                        + "\t\tTotal Bandwidth (in KB): %s\n"
                        + "\t\tIP Addresses:\n", typeID, nInfo.getLastConn(), nInfo.getUpload(), nInfo.getDownload(), nInfo.getBandwidth());
                for (String ip : nInfo.getIps()){
                    printing += String.format("\t\t\t%s\n", ip);
                }
            }
            System.out.println(printing);
        }
    }
    
}
