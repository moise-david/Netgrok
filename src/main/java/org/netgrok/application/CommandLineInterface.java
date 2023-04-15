package org.netgrok.application;

import java.io.Console;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.netgrok.components.Devices;
import org.netgrok.components.Networks;
import org.netgrok.components.PublicSuffix;
import org.netgrok.runtime.Netgrok;

public class CommandLineInterface {

    private Netgrok netgrok;
    private final ScheduledExecutorService EXEC = Executors.newScheduledThreadPool(3);
    private PublicSuffix ps = new PublicSuffix();

    private final Runnable COMMANDLINE = new Runnable() {
        @Override
        public void run() {
            try {
                Thread.sleep(1000);
                Console c = System.console();
                String[] q;
                while (true) {
                    q = c.readLine("NetGrok> ").split(" ");
                    switch (q[0]) {
                        case "exit":
                            netgrok.shutdown();
                            EXEC.shutdown();
                            return;
                        default:
                            handleQuery(q);
                    }
                }
            } catch (InterruptedException ex) {
                Logger.getLogger(CommandLineInterface.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    };

    private final Runnable NETGROK = new Runnable() {
        @Override
        public void run() {
            netgrok.initialize();
            netgrok.start();
        }
    };

    public CommandLineInterface(String[] args) {
        EXEC.execute(new Thread(COMMANDLINE));
        netgrok = new Netgrok(args);
    }

    public void start() {
        EXEC.execute(new Thread(NETGROK));
        EXEC.scheduleAtFixedRate(netgrok.getAgeOffClass(), 60, 60, TimeUnit.SECONDS);
    }

    public void handleQuery(String[] q) {
        try {
            ResultSet rs = null;
            ResultSetMetaData rsmd;
            if (q.length >= 2) {
                if ("show".equalsIgnoreCase(q[0])) {
                    if ("History".equalsIgnoreCase(q[1])) rs = netgrok.getConnection().createStatement().executeQuery("Select * from History");
                    else if ("networks".equalsIgnoreCase(q[1])) {
                        Networks networks = netgrok.getNetworks();
                        System.out.println(networks.printSimple());
                    }
                    else if ("websites".equalsIgnoreCase(q[1])) {
                        System.out.println(netgrok.getWebsites());
                    }
                    else if ("devices".equalsIgnoreCase(q[1])) {
                        Devices devices = netgrok.getDevices();
                        System.out.println(devices);
                    }
                }
            }
            if (rs != null) {
                rsmd = rs.getMetaData();
                int columns = rsmd.getColumnCount();
                for (int i = 1; i < columns; i++) System.out.format("%-40s\t", rsmd.getColumnName(i));
                System.out.println(rsmd.getColumnName(columns) + "\n");
                while (rs.next()) {
                    for (int i = 1; i <= columns; i++) {
                        if (i == columns) {
                            System.out.println(rs.getString(i));
                        } else {
                            System.out.format("%-40s\t", rs.getString(i));
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            Logger.getLogger(CommandLineInterface.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
