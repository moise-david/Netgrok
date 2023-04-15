/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.netgrok.components;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author EECS
 */
public class AgeOffTest {
    
    public AgeOffTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getAgeOff method, of class AgeOff.
     */
    @Test
    public void testGetAgeOff() {
        System.out.println("getAgeOff");
        AgeOff instance = null;
        int expResult = 0;
        int result = instance.getAgeOff();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of setAgeOff method, of class AgeOff.
     */
    @Test
    public void testSetAgeOff() {
        System.out.println("setAgeOff");
        int ageOff = 0;
        AgeOff instance = null;
        instance.setAgeOff(ageOff);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getAgeOffUnit method, of class AgeOff.
     */
    @Test
    public void testGetAgeOffUnit() {
        System.out.println("getAgeOffUnit");
        AgeOff instance = null;
        String expResult = "";
        String result = instance.getAgeOffUnit();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of setAgeOffUnit method, of class AgeOff.
     */
    @Test
    public void testSetAgeOffUnit() {
        System.out.println("setAgeOffUnit");
        String ageOffUnit = "";
        AgeOff instance = null;
        instance.setAgeOffUnit(ageOffUnit);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of run method, of class AgeOff.
     */
    @Test
    public void testRun() {
        System.out.println("run");
        AgeOff instance = null;
        instance.run();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
}
