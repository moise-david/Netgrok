package org.netgrok.components;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.netgrok.runtime.Netgrok;

public class AgeOff implements Runnable {

    private final Netgrok netgrok;
    private int ageOff = 5;
    private String ageOffUnit = "minutes";
    private final Set<String> TIME_UNIT_OPTIONS = new HashSet<>(Arrays.asList(new String[]{"seconds", "minutes", "hours", "days"}));

    public int getAgeOff() { return ageOff; }
    public void setAgeOff(int ageOff) { if (ageOff > 0) this.ageOff = ageOff; }
    public String getAgeOffUnit() { return ageOffUnit; }
    public void setAgeOffUnit(String ageOffUnit) { if (TIME_UNIT_OPTIONS.contains(ageOffUnit)) this.ageOffUnit = ageOffUnit; }

    public AgeOff(Netgrok netgrok) { this.netgrok = netgrok; }

    @Override
    public void run() {
        try {
            String ageOffScript = String.format("DELETE FROM History WHERE LastConnection < datetime('now','localtime',"
                    + "'-%d %s');", ageOff, ageOffUnit);
            netgrok.getConnection().createStatement().execute(ageOffScript);
        } catch (SQLException ex) {
            System.out.println(ex);
        }
    }

}
