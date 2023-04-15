package org.netgrok.components;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MacVendorLookup {
    private HashMap<String, HashMap> macVendors;
    
    public MacVendorLookup() {
        this.macVendors = new HashMap();
        InputStream inputStream = ClassLoader.getSystemResourceAsStream("macvendors.txt");
        try (Scanner sc = new Scanner(inputStream, "UTF-8")) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    String[] lineSplit = line.split("\\t");
                    String[] macs = lineSplit[0].toLowerCase().split(":");
                    if (macs.length == 3) mapMacs(macVendors, macs, 0, lineSplit[lineSplit.length-1]);
                }
            }
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ex) {
                    Logger.getLogger(PublicSuffix.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    public String parseMac(String mac) {
        String[] lineSplit = mac.split(":");
        return parse(macVendors, lineSplit, 0);
    }

    private void mapMacs(HashMap cur, String[] line, int pos, String label) {
        String curKey = line[pos];
        if (pos < 2) {
            if (!cur.containsKey(curKey)) cur.put(curKey, new HashMap());
            mapMacs((HashMap) cur.get(curKey), line, pos + 1, label);
        }
        else cur.put(curKey, label);
    }
    
    private String parse(HashMap cur, String[] line, int pos){
        String curKey = line[pos];
        if (cur.containsKey(curKey) && pos < 3) {
            if (pos < 2) return parse((HashMap) cur.get(curKey), line, pos + 1);
            else return (String) cur.get(curKey);
        }
        else return null;
    }
}
