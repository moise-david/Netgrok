package org.netgrok.components;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.text.WordUtils;

public class PublicSuffix {

    private HashMap<String, HashMap> suffixData;

    public PublicSuffix() {
        this.suffixData = new HashMap();
        InputStream inputStream = ClassLoader.getSystemResourceAsStream("public_suffix_list.txt");
        try (Scanner sc = new Scanner(inputStream, "UTF-8")) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                if (!line.isEmpty() && !line.startsWith("//")) {
                    String[] lineSplit = line.split("\\.");
                    mapDomains(suffixData, lineSplit, lineSplit.length-1);
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

    public String parseDomain(String dns) {
        if (dns != null){
            String[] lineSplit;
            if (dns.startsWith("www")) lineSplit = dns.substring(dns.indexOf('.')+1).split("\\.");
            else lineSplit = dns.split("\\.");
            return parse(suffixData, lineSplit, lineSplit.length-1);
        }
        else return null;
    }

    private void mapDomains(HashMap cur, String[] line, int pos) {
        if (pos >= 0) {
            if (!cur.containsKey(line[pos])) cur.put(line[pos], new HashMap());
            mapDomains((HashMap) cur.get(line[pos]), line, pos - 1);
        }
    }
    
    private String parse(HashMap cur, String[] line, int pos){
        if (pos > 0){
            if (cur.containsKey(line[pos])) return parse((HashMap) cur.get(line[pos]), line, pos - 1);
            else if (cur.containsKey("*")) return parse((HashMap) cur.get("*"), line, pos - 1);
            else return null;
        }
        else return WordUtils.capitalize(line[pos]);
    }
}
