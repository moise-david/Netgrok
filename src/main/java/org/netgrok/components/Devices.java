package org.netgrok.components;

import java.util.HashMap;
import java.util.Set;
import java.util.TreeSet;

public class Devices {
    
    private final HashMap<String, DeviceInfo> ds = new HashMap<>();
    private final PublicSuffix suffix = new PublicSuffix();

    public class DeviceInfo {
        HashMap<String, NetworkInfo> networks = new HashMap<>();
        String mac;
        String title;

        private DeviceInfo(String mac, String title) {
           this.mac = mac;
           this.title = title;
        }

        private void updateNetworkInfo(String ip, String title, double up, double down, long lastConn) {
            if (networks.containsKey(title)) networks.get(title).update(ip, up, down, lastConn);
            else {
                NetworkInfo n = new NetworkInfo();
                n.update(ip, up, down, lastConn);
                networks.put(title, n);
            }
        }
    }
    
    public void addDevice(String ip, String mac, String title) { ds.put(ip, new DeviceInfo(mac, title)); }
    public boolean contains(String ipKey){ return ds.containsKey(ipKey); }
    
    public void addNetworkInfo(String srcIp, String srcTitle, String dstIp, String dstTitle, double bytes, long lastConn){
        if (srcTitle == null && ds.containsKey(srcIp)) ds.get(srcIp).updateNetworkInfo(dstIp, dstTitle, bytes, 0, lastConn);
        if (dstTitle == null && ds.containsKey(dstIp)) ds.get(dstIp).updateNetworkInfo(srcIp, srcTitle, 0, bytes, lastConn);
    }
    
    public HashMap<String, DeviceInfo> getDevices(){ return ds; }
    
    @Override
    public String toString(){
        String printing = "";
        TreeSet<String> sortedOrgs = new TreeSet<>();
        for (String k : ds.keySet()){
            DeviceInfo info = ds.get(k);
            if (info.title != null) {
                printing += String.format("Device '%s' connected to the following websites:\n\n", info.title);
                info.networks.keySet().forEach(x -> {
                    String parsed;
                    if (x != null && !info.networks.get(x).ips.contains(x) && (parsed = suffix.parseDomain(x)) != null) sortedOrgs.add(parsed);
                });
                for (String title : sortedOrgs) printing += ("\t" + title + "\n");
                printing += "\n\n";
            }
        }
        return printing;
    }
}
