package org.netgrok;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import org.netgrok.application.ClickableGUI;
import org.netgrok.application.CommandLineInterface;
import org.netgrok.runtime.Netgrok;

public class Main {

    public static void main(String[] args) {
    
        Netgrok netgrok = new Netgrok(new String[]{"-i", "192.168.137.1"});
        Runnable NETGROK = new Runnable() {
            @Override
            public void run() {
                netgrok.initialize();
                netgrok.start();
            }
        };
        ScheduledExecutorService EXEC = Executors.newScheduledThreadPool(1);
        EXEC.execute(new Thread(NETGROK));
        ClickableGUI gui = new ClickableGUI(netgrok);
        gui.main(args);
//        CommandLineInterface cli = new CommandLineInterface(args);
//        cli.start();
    }
}
