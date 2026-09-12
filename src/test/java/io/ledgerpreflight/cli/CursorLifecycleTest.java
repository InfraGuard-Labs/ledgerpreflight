package io.ledgerpreflight.cli;
import org.junit.jupiter.api.Test;
import java.io.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class CursorLifecycleTest {
    private SessionTerminal fake(Reader reader,StringWriter output){return new SessionTerminal(reader,new PrintWriter(output),true,76){@Override protected String terminalMode(String...args){return "saved";}};}
    @Test void cursorRestoredOnEnterAndQ()throws Exception {for(String input:List.of("\n","q","\u0003")){StringWriter output=new StringWriter();fake(new StringReader(input),output).choose("",List.of("Continue","Exit"));String text=output.toString();assertTrue(text.contains("\u001b[?25l"));assertTrue(text.contains("\u001b[?25h"));assertTrue(text.lastIndexOf("\u001b[?25h")>text.lastIndexOf("\u001b[?25l"));assertTrue(text.contains("> Continue"));}}
    @Test void cursorRestoredOnUnexpectedReaderException(){StringWriter output=new StringWriter();Reader broken=new Reader(){public int read(char[] b,int o,int n)throws IOException{throw new IOException("synthetic reader failure");}public void close(){}};assertThrows(IOException.class,()->fake(broken,output).choose("",List.of("Continue")));assertTrue(output.toString().contains("\u001b[?25h"));}
    @Test void arrowNavigationChangesSelection()throws Exception{StringWriter output=new StringWriter();assertEquals(1,fake(new StringReader("\u001b[B\n"),output).choose("",List.of("Continue","Exit")));assertTrue(output.toString().contains("> Exit"));}
    @Test void plainOutputHasNoCursorSequences()throws Exception{StringWriter output=new StringWriter();new SessionTerminal(new StringReader("1\n"),new PrintWriter(output),false,76).choose("",List.of("Continue"));assertFalse(output.toString().contains("\u001b"));}
}
