/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.netgrok.components;

import static java.lang.Long.max;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;

/**
 *
 * @author x87175
 */
public class NetworkInfo {
    
    HashSet<String> ips = new HashSet();
    double upload = 0;
    double download = 0;
    long lastConn = 0;
    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public void update(String ip, double u, double d, long last){
        ips.add(ip);
        upload += u;
        download += d;
        lastConn = max(last, lastConn);
    }
    public HashSet<String> getIps() { return ips; }
    public double getUpload() { return upload; }
    public double getDownload() { return download; }
    public double getBandwidth() { return upload + download; }
    public String getLastConn() {
        Date date = new Date(lastConn);
        return format.format(date);
    }
}
