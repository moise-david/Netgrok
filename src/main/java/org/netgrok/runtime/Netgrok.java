package org.netgrok.runtime;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.log4j.BasicConfigurator;
import org.netgrok.components.AgeOff;
import org.netgrok.components.CaptureLoader;
import org.netgrok.components.CaptureRunner;
import org.netgrok.components.Devices;
import org.netgrok.components.Networks;
import org.netgrok.components.PublicSuffix;

public class Netgrok {

    private CaptureRunner runner;
    private Connection connection;
    private CaptureLoader loader;
    private final AgeOff ageOff;
    private int fidelity = 5;
    private String fidelityUnit = "minutes";
    private String[] options = null;
    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private PublicSuffix suffix = new PublicSuffix();
    private Devices devices = new Devices();
    
    public Netgrok() {
        BasicConfigurator.configure();
        org.apache.log4j.Logger.getRootLogger().setLevel(org.apache.log4j.Level.OFF);
        this.ageOff = new AgeOff(this);
    }

    public Netgrok(String[] args) {
        BasicConfigurator.configure();
        org.apache.log4j.Logger.getRootLogger().setLevel(org.apache.log4j.Level.OFF);
        BasicConfigurator.configure();
        this.ageOff = new AgeOff(this);
        this.options = args;
    }
    
    public Netgrok(String file){
        BasicConfigurator.configure();
        this.ageOff = new AgeOff(this);
    }

    public void initialize(){
        this.loader = new CaptureLoader(options);
        this.runner = new CaptureRunner(this.loader);
        this.connection = this.runner.getDatabase().getConnection();
    }
    
    public void fromFile(String file){
        this.loader = new CaptureLoader(file);
        this.runner = new CaptureRunner(this.loader);
        this.connection = this.runner.getDatabase().getConnection();
    }

    public void setAgeOff(int time, String timeUnit){
        this.ageOff.setAgeOff(time);
        this.ageOff.setAgeOffUnit(timeUnit);
    }
    
    public void setFidelity(int time, String timeUnit){
        this.fidelity = time;
        this.fidelityUnit = timeUnit;
    }

    public void setFidelityUnit(String timeUnit){ this.fidelityUnit = timeUnit; }
    public Connection getConnection() { return this.connection; }
    public long getAgeOff() { return this.ageOff.getAgeOff(); }
    public AgeOff getAgeOffClass() { return this.ageOff; }
    public String getAgeOffUnit() { return this.ageOff.getAgeOffUnit(); }
    public long getFidelity() { return this.fidelity; }
    public String getFidelityUnit() { return this.fidelityUnit; }
    public void shutdown() { this.runner.shutdown(); }
    public void start(){ this.runner.start();}
    
    public Networks getNetworks(){
        Networks networks = new Networks();
        try {
            Connection c = getConnection();
            ResultSet rs = c.createStatement().executeQuery("SELECT IpAddress, HTTPHeader, DNSName, SSLOrgName, "
                + "(Select IFNULL(SUM(Kilobytes),0) FROM History WHERE Destination=IpAddress) as Upload, "
                + "(Select IFNULL(SUM(Kilobytes), 0) FROM History WHERE Source=IpAddress) as Download, "
                + "(Select MAX(LastConnection) FROM History WHERE Source=IpAddress or Destination=IpAddress) as LastConnection from ExtHosts "
                + "GROUP BY IpAddress ORDER BY SSLOrgName ASC, DNSName ASC, IpAddress ASC");
            while (rs.next()){
                networks.addNetwork(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getDouble(5), rs.getDouble(6), format.parse(rs.getString(7)).getTime());
            }
        } catch (SQLException | ParseException ex) {
            Logger.getLogger(Netgrok.class.getName()).log(Level.SEVERE, null, ex);
        }
        return networks;
    }
    
    public Devices getDevices(){
        devices = new Devices();
        try {
            ResultSet rs = this.connection.createStatement().executeQuery("SELECT IpAddress, MacAddress, COALESCE(Hostname, DeviceManufacturer) as Title FROM IntHosts");
            while (rs.next()){
                devices.addDevice(rs.getString(1), rs.getString(2), rs.getString(3));
            }
            rs = this.connection.createStatement().executeQuery("SELECT h.Source, COALESCE(e1.DNSName, e1.HTTPHeader) as SourceWebsite, "
                    + "h.Destination, COALESCE(e2.DNSName, e2.HTTPHeader) as DestinationWebsite, h.Kilobytes, h.LastConnection "
                    + "FROM HISTORY h "
                    + "LEFT JOIN EXTHosts e1 on h.Source = e1.IpAddress "
                    + "LEFT JOIN EXTHosts e2 on h.Destination = e2.IpAddress");
            while (rs.next()){
                devices.addNetworkInfo(rs.getString(1), suffix.parseDomain(rs.getString(2)), rs.getString(3), suffix.parseDomain(rs.getString(4)), rs.getDouble(5), format.parse(rs.getString(6)).getTime());
            }
        } catch (SQLException | ParseException ex) {
            Logger.getLogger(Netgrok.class.getName()).log(Level.SEVERE, null, ex);
        }
        return devices;
    }
    
    public HashMap<String, Devices.DeviceInfo> getDeviceMap(){ return devices.getDevices(); }

    public String getWebsites() {
        String printing = "";
        try {
            TreeSet<String> expConn = new TreeSet<>();
            TreeSet<String> impConn = new TreeSet<>();
            ResultSet rs = this.connection.createStatement().executeQuery("SELECT COALESCE(DNSName, HTTPHeader) as WEBSITE from ExtHosts WHERE WEBSITE IS NOT NULL GROUP BY WEBSITE");
            while (rs.next()){
                String dns = suffix.parseDomain(rs.getString(1));
                if (dns != null) expConn.add(dns);
                else impConn.add(rs.getString(1));
            }
            
            printing += "Explicit communications:\n";
            for (String e : expConn) printing += "\t" + e + "\n";
            printing += "\n";
            
            printing += "Implicit communications:\n";
            for (String i : impConn) printing += "\t" + i + "\n";
        } catch (SQLException ex) { 
            Logger.getLogger(Netgrok.class.getName()).log(Level.SEVERE, null, ex);
        }
        return printing;
    }

}
