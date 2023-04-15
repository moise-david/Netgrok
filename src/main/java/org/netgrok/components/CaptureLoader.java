package org.netgrok.components;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;

public class CaptureLoader {

    private PcapNetworkInterface networkInterface;
    private PcapAddress address;
    private PcapHandle handle;
    private int[] networkAddress = new int[4];
    private int[] broadcastAddress = new int[4];
    private Options options;
    private CommandLine commandLine;
    private final int SNAP_LENGTH = 65536;

    public CaptureLoader(String[] args) {
        this.createOptions();
        this.load(args);
    }

    public CaptureLoader(String file) {
        try {
            defaultNetInterface();
            setNetworkBroadcastAddress();
            fromFile(file);
        } catch (PcapNativeException ex) {
            Logger.getLogger(CaptureLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public CaptureLoader() {
        defaultNetInterface();
        setNetworkBroadcastAddress();
        liveInterface();
    }

    private void createOptions() {
        this.options = new Options();
        this.options.addOption("i", "interface", true, "Provide a network interface in which you would like to capture data."
                + "If there are any issues with loading the interface, NetGrok will default to the recommended interface.");
        this.options.addOption("a", "ageoff", false, "Specifies the age off time frame. The default of 1 hour is used if the "
                + "user does not provide an ageoff time limit.");
    }

    private void load(String[] args) {
        try {
            this.commandLine = new DefaultParser().parse(this.options, args);

            // Read from pcap file
            if (commandLine.hasOption('f')) {
                fromFile(commandLine.getOptionValue('f'));
            } else {
                // Load network interface
                if (commandLine.hasOption('i')) {
                    String specInterface = commandLine.getOptionValue('i');
                    PcapNetworkInterface p = Pcaps.getDevByAddress(InetAddress.getByName(specInterface));
                    if (p != null) {
                        this.networkInterface = p;
                        this.address = findIPv4Address(this.networkInterface.getAddresses());
                    }
                }

                if (this.networkInterface == null) {
                    defaultNetInterface();
                }

                //Create integer version of network and broadcast address from given byte form
                setNetworkBroadcastAddress();

                liveInterface();
            }

        } catch (PcapNativeException | ParseException | UnknownHostException ex) {
            Logger.getLogger(CaptureLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private PcapAddress findIPv4Address(List<PcapAddress> addresses) {
        Predicate<PcapAddress> IPv4filter = a -> a.getAddress().isLoopbackAddress() || a.getAddress().toString().contains(":");
        addresses.removeIf(IPv4filter);
        if (!addresses.isEmpty()) {
            return addresses.get(0);
        }
        return null;
    }

    private void defaultNetInterface() {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            devices.removeIf(x -> x.getAddresses().isEmpty());
            PcapNetworkInterface d = devices.get(0);
            System.out.println(String.format("Interface selected: %s", d.getDescription()));
            this.networkInterface = d;
            this.address = findIPv4Address(d.getAddresses());
        } catch (PcapNativeException ex) {
            Logger.getLogger(CaptureLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void setNetworkBroadcastAddress() {
        byte[] badd = this.address.getBroadcastAddress().getAddress();
        byte[] mask = this.address.getNetmask().getAddress();
        for (int i = 0; i < badd.length; i++) {
            this.broadcastAddress[i] = badd[i] & 0xFF;
        }
        for (int i = 0; i < mask.length; i++) {
            this.networkAddress[i] = mask[i] & badd[i] & 0xFF;
        }
    }

    private void printSettings() {
        System.out.format("\nNetGrok is currently running on %s.\n"
                + "Selected/Loaded interface: %s\n"
                + "\tNetwork address: %s.%s.%s.%s\n"
                + "\tBroadcast address: %s\n"
                + "\tYour IPv4 address: %s\n",
                System.getProperty("os.name"), this.networkInterface.getName(),
                this.networkAddress[0], this.networkAddress[1], this.networkAddress[2], this.networkAddress[3],
                this.address.getBroadcastAddress().getHostAddress(), this.address.getAddress().getHostName());
    }

    private void fromFile(String file) throws PcapNativeException {
            this.handle = Pcaps.openOffline(file);
    }

    private void liveInterface() {
        try {
            this.handle = this.networkInterface.openLive(SNAP_LENGTH, PromiscuousMode.PROMISCUOUS, 1);
        } catch (PcapNativeException ex) {
            Logger.getLogger(CaptureLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public PcapHandle getHandle() {
        return handle;
    }

    public CommandLine getCommandLine() {
        return commandLine;
    }

    public int[] getNetworkAddress() {
        return networkAddress;
    }

    public int[] getBroadcastAddress() {
        return broadcastAddress;
    }
}
