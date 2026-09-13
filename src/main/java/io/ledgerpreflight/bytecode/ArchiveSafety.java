package io.ledgerpreflight.bytecode;

import java.io.*;
import java.nio.file.*;
import java.util.zip.ZipFile;

/** Bound the central directory before ZipFile allocates it. No input entry is extracted. */
public final class ArchiveSafety {
    private ArchiveSafety(){}
    public static ZipFile open(Path path,int maxEntries)throws IOException {
        try(RandomAccessFile file=new RandomAccessFile(path.toFile(),"r")){
            long size=file.length();int length=(int)Math.min(size,65557);byte[] tail=new byte[length];file.seek(size-length);file.readFully(tail);
            boolean valid=false;
            for(int i=length-22;i>=0;i--)if(u32(tail,i)==0x06054b50L&&i+22+u16(tail,i+20)==length){
                long bytes=u32(tail,i+12),offset=u32(tail,i+16);int entries=u16(tail,i+10);
                if(u16(tail,i+4)!=0||u16(tail,i+6)!=0||u16(tail,i+8)!=entries||entries==65535||bytes==0xffffffffL||offset==0xffffffffL)throw new IOException("Split/ZIP64 archive requires unsupported directory coverage");
                if(entries>maxEntries||bytes>8L*1024*1024)throw new IOException("Archive central-directory safety limit reached");
                if(offset+bytes!=size-length+i)throw new IOException("Invalid archive central-directory bounds");valid=true;break;
            }
            if(!valid)throw new IOException("Truncated archive: central directory missing");
        }
        return new ZipFile(path.toFile());
    }
    private static int u16(byte[] b,int i){return (b[i]&255)|((b[i+1]&255)<<8);}
    private static long u32(byte[] b,int i){return (b[i]&255L)|((b[i+1]&255L)<<8)|((b[i+2]&255L)<<16)|((b[i+3]&255L)<<24);}
}
