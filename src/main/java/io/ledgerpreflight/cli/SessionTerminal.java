package io.ledgerpreflight.cli;

import io.ledgerpreflight.evidence.Sanitizer;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Small Linux terminal adapter. Raw mode exists only while choosing a menu item. */
public class SessionTerminal {
    private final Reader input;
    private final PrintWriter out;
    private boolean advanced;
    private final int width;
    public SessionTerminal(Reader input, PrintWriter out, boolean advanced, int width) {
        this.input=input; this.out=out; this.advanced=advanced; this.width=Math.max(30,Math.min(100,width));
    }
    public static SessionTerminal system(PrintWriter out, boolean plain) {
        return new SessionTerminal(new InputStreamReader(System.in,StandardCharsets.UTF_8),out,
            !plain && System.console()!=null && System.getenv("TERM")!=null && !System.getenv("TERM").equals("dumb"),columns());
    }
    private static int columns() {
        try { String[] size=stty("size").strip().split(" "); return Integer.parseInt(size[size.length-1]); }
        catch(Exception e){return 76;}
    }
    public static String safe(String text) {
        return Sanitizer.redact(text).replaceAll("[\\p{Cntrl}&&[^\\n\\t]]","").replaceAll("[\\u202a-\\u202e\\u2066-\\u2069]","");
    }
    public void text(String text) {
        for(String line:safe(text).split("\n",-1)) {
            while(line.length()>width) { int at=line.lastIndexOf(' ',width);if(at<1)at=width;out.println(line.substring(0,at));line=line.substring(at).stripLeading(); }
            out.println(line);
        }
        out.flush();
    }
    public void screen(){if(advanced){out.print("\u001b[2J\u001b[H");out.flush();}}
    public String ask(String prompt)throws IOException {
        text(prompt+" (blank returns)");
        StringBuilder value=new StringBuilder();int c;
        while((c=input.read())!=-1 && c!='\n') {if(c==3||c==4)return "";if(c!='\r')value.append((char)c);if(value.length()>4096)throw new IOException("Input is too long");}
        return value.toString().strip();
    }
    public int choose(String title,List<String> labels)throws IOException {
        if(advanced) {
            String saved;
            try {saved=stty("-g").strip();stty("-icanon","-echo","min","0","time","1");}
            catch(Exception e){advanced=false;return choose(title,labels);}
            Thread restore=new Thread(()->{try{stty(saved);}catch(Exception ignored){}},"restore-terminal");
            Runtime.getRuntime().addShutdownHook(restore);
            try {
                int selected=0; draw(title,labels,selected);
                while(true) {
                    int c=input.read();
                    if(c==-1)continue;
                    if(c==3||c==4||c=='q')return -1;
                    if(c=='\r'||c=='\n')return selected;
                    if(c==27){int next=input.read();if(next!='['&&next!='O')return -1;c=input.read();if(c=='A')selected=(selected+labels.size()-1)%labels.size();else if(c=='B')selected=(selected+1)%labels.size();}
                    else if(c=='k')selected=(selected+labels.size()-1)%labels.size();
                    else if(c=='j')selected=(selected+1)%labels.size();
                    else continue;
                    draw(title,labels,selected);
                }
            } finally {try{stty(saved);}catch(Exception ignored){}Runtime.getRuntime().removeShutdownHook(restore);out.print("\u001b["+(labels.size()+1)+"B\r\n");out.flush();}
        }
        text("\n"+title);
        for(int i=0;i<labels.size();i++)text((i+1)+". "+labels.get(i));
        while(true){String s=ask("Choose an action; q exits");if(s.isEmpty()||s.equalsIgnoreCase("q"))return -1;
            try{int n=Integer.parseInt(s);if(n>=1&&n<=labels.size())return n-1;}catch(NumberFormatException ignored){}
            text("Choose one of the displayed actions.");}
    }
    private void draw(String title,List<String> labels,int selected) {
        // Redraw only this menu, leaving assessment and explanations in scrollback.
        out.print("\r\u001b[J");out.println(safe(title));
        for(int i=0;i<labels.size();i++){String s=safe(labels.get(i));out.println((i==selected?"❯ ":"  ")+(s.length()>width-3?s.substring(0,width-4)+"…":s));}
        out.print("↑/↓ select · Enter open · q back\u001b["+(labels.size()+1)+"A\r");out.flush();
    }
    private static String stty(String...args)throws Exception {
        List<String> command=new ArrayList<>(List.of("/bin/stty"));command.addAll(List.of(args));
        Process p=new ProcessBuilder(command).redirectInput(new File("/dev/tty")).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        if(!p.waitFor(2,TimeUnit.SECONDS)){p.destroyForcibly();throw new IOException("Terminal unavailable");}
        if(p.exitValue()!=0)throw new IOException("Terminal unavailable");
        return new String(p.getInputStream().readNBytes(1024),StandardCharsets.UTF_8);
    }
}
