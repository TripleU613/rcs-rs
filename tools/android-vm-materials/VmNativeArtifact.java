/* Copyright (C) 2026 rcs-rs contributors. SPDX-License-Identifier: Apache-2.0
 * Observed vendor loader d(): root library.txt -> root lib<selector>.so.
 * Caller MUST authenticate the whole APK first. This parser is NOT signature trust,
 * extraction, System.load, ABI emulation or a universal Android/native loader.
 */
package org.rcsrs.standalonecheckin;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;
public final class VmNativeArtifact {
    public static final int APK_MAX=6*1024*1024,LIBRARY_MAX=6*1024*1024;
    public static final class Materials {
        private final String name;private final byte[] library,sha;
        private Materials(String name,byte[] library,byte[] sha){this.name=name;this.library=library.clone();this.sha=sha.clone();}
        public String libraryName(){return name;}
        public byte[] clonedLibraryBytes(){return library.clone();}
        public byte[] clonedSha256(){return sha.clone();}
    }
    public static Materials inspect(File authenticatedApk)throws IOException{
        if(authenticatedApk==null || !Files.isRegularFile(authenticatedApk.toPath(),LinkOption.NOFOLLOW_LINKS) ||
            authenticatedApk.length()<=0 || authenticatedApk.length()>APK_MAX)throw new IOException();
        try(ZipFile zip=new ZipFile(authenticatedApk)){
            Set<String> names=new HashSet<>();Enumeration<? extends ZipEntry> entries=zip.entries();long total=0;
            while(entries.hasMoreElements()){
                ZipEntry entry=entries.nextElement();String name=entry.getName();
                if(names.size()>=4096 || !names.add(name) || !validPath(name,entry.isDirectory()) || entry.getSize()<0 ||
                    entry.getSize()>APK_MAX || entry.getCompressedSize()<0 || entry.getCompressedSize()>APK_MAX ||
                    (entry.getMethod()!=ZipEntry.STORED && entry.getMethod()!=ZipEntry.DEFLATED))throw new IOException();
                total+=entry.getSize();if(total>32L*1024*1024)throw new IOException();
            }
            byte[] selector=read(zip,"library.txt",128);StringBuilder text=new StringBuilder();
            for(byte b:selector){int c=b&255;if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'))throw new IOException();text.append((char)c);}
            if(text.length()==0)throw new IOException();String name="lib"+text+".so";byte[] library=read(zip,name,LIBRARY_MAX);
            validateElf(library);return new Materials(name,library,sha(library));
        }
    }
    private static boolean validPath(String name,boolean directory){
        if(name==null || !name.matches("[A-Za-z0-9_./-]{1,240}") || name.startsWith("/"))return false;
        String[] parts=name.split("/",-1);
        for(int i=0;i<parts.length;i++)if(parts[i].equals(".") || parts[i].equals("..") ||
            (parts[i].isEmpty() && !(directory && i==parts.length-1)))return false;
        return true;
    }
    private static byte[] read(ZipFile zip,String name,int cap)throws IOException{
        ZipEntry entry=zip.getEntry(name);if(entry==null || entry.isDirectory() || entry.getSize()<=0 || entry.getSize()>cap || entry.getCrc()<0)throw new IOException();
        ByteArrayOutputStream out=new ByteArrayOutputStream();CRC32 crc=new CRC32();
        try(InputStream in=zip.getInputStream(entry)){
            byte[] block=new byte[8192];int n;while((n=in.read(block))!=-1){if(n<=0 || n>cap-out.size())throw new IOException();out.write(block,0,n);crc.update(block,0,n);}
        }
        if(out.size()!=entry.getSize() || crc.getValue()!=entry.getCrc())throw new IOException();return out.toByteArray();
    }
    private static byte[] sha(byte[] bytes)throws IOException{try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(GeneralSecurityException invalid){throw new IOException();}}
    private static long positiveOffset(ByteBuffer b,int at)throws IOException{long n=b.getLong(at);if(n<0)throw new IOException();return n;}
    private static void table(long start,int count,int size,int length)throws IOException{if(start<64 || count<=0 || start>length || (long)count*size>length-start)throw new IOException();}
    private static void validateElf(byte[] data)throws IOException{
        if(data.length<64 || data[0]!=127 || data[1]!='E' || data[2]!='L' || data[3]!='F' || data[4]!=2 || data[5]!=1 || data[6]!=1)throw new IOException();
        ByteBuffer b=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if(b.getShort(16)!=3 || b.getShort(18)!=183 || b.getInt(20)!=1 || b.getShort(52)!=64 || b.getShort(54)!=56)throw new IOException();
        long ph=positiveOffset(b,32);int count=b.getShort(56)&65535;table(ph,count,56,data.length);int loads=0;
        for(int i=0;i<count;i++){
            int at=(int)(ph+(long)i*56);if(b.getInt(at)!=1)continue;loads++;
            long offset=positiveOffset(b,at+8),files=positiveOffset(b,at+32),memory=positiveOffset(b,at+40);
            if(offset>data.length || files>data.length-offset || memory<files)throw new IOException();
        }
        if(loads==0)throw new IOException();long sections=positiveOffset(b,40);int n=b.getShort(60)&65535;
        if(sections==0){if(n!=0)throw new IOException();}else{if(b.getShort(58)!=64)throw new IOException();table(sections,n,64,data.length);}
    }
    private interface Trial{void run()throws Exception;}
    private static int rejected;
    private static void bad(Trial trial)throws Exception{try{trial.run();}catch(IOException expected){rejected++;return;}throw new AssertionError();}
    private static void check(boolean b){if(!b)throw new AssertionError();}
    private static byte[] elf(){
        ByteBuffer b=ByteBuffer.allocate(128).order(ByteOrder.LITTLE_ENDIAN);b.put(new byte[]{127,'E','L','F',2,1,1});
        b.putShort(16,(short)3);b.putShort(18,(short)183);b.putInt(20,1);b.putLong(32,64);
        b.putShort(52,(short)64);b.putShort(54,(short)56);b.putShort(56,(short)1);
        b.putInt(64,1);b.putInt(68,5);b.putLong(96,128);b.putLong(104,128);b.putLong(112,4096);return b.array();
    }
    private static byte[] zip(String[] names,byte[][] values)throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();try(ZipOutputStream z=new ZipOutputStream(out)){
            for(int i=0;i<names.length;i++){ZipEntry e=new ZipEntry(names[i]);z.putNextEntry(e);z.write(values[i]);z.closeEntry();}
        }return out.toByteArray();
    }
    private static byte[] rename(byte[] zip,String from,String to)throws Exception{
        byte[] value=zip.clone(),a=from.getBytes("US-ASCII"),b=to.getBytes("US-ASCII");check(a.length==b.length);int count=0;
        for(int i=0;i<=value.length-a.length;i++){boolean match=true;for(int j=0;j<a.length;j++)if(value[i+j]!=a[j])match=false;
            if(match){System.arraycopy(b,0,value,i,b.length);count++;i+=a.length-1;}}
        check(count==2);return value;
    }
    private static Materials inspectFixture(Path file,byte[] zip)throws IOException{Files.write(file,zip);return inspect(file.toFile());}
    public static void main(String[] args)throws Exception{
        Path dir=Files.createTempDirectory("rcsrs-native-fixture-");Path file=dir.resolve("fixture.apk");
        try{
            byte[] valid=zip(new String[]{"library.txt","libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),elf()});
            Materials m=inspectFixture(file,valid);check(m.libraryName().equals("libfixture.so") && m.clonedLibraryBytes().length==128 && m.clonedSha256().length==32);
            byte[] copy=m.clonedLibraryBytes();copy[0]=0;check(m.clonedLibraryBytes()[0]==127);
            copy=m.clonedSha256();copy[0]^=1;check(!Arrays.equals(copy,m.clonedSha256()));
            for(String selector:Arrays.asList("","fixture\n","fixture\r","../fixture","a/b","a\\b","fixture.so","a\u0000b","λ")){
                byte[] z=zip(new String[]{"library.txt","libfixture.so"},new byte[][]{selector.getBytes("UTF-8"),elf()});bad(()->inspectFixture(file,z));
            }
            for(int offset:new int[]{0,4,5,6,16,18,20,32,40,52,54,56,96,104}){
                byte[] broken=elf();if(offset==104)broken[offset]=0;else broken[offset]^=1;byte[] z=zip(new String[]{"library.txt","libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),broken});bad(()->inspectFixture(file,z));
            }
            bad(()->inspectFixture(file,zip(new String[]{"library.txt"},new byte[][]{"fixture".getBytes("US-ASCII")})));
            bad(()->inspectFixture(file,zip(new String[]{"libfixture.so"},new byte[][]{elf()})));
            bad(()->inspectFixture(file,zip(new String[]{"library.txt","../other","libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),new byte[0],elf()})));
            for(int n:new int[]{0,1,63,64,100}){byte[] shortElf=Arrays.copyOf(elf(),n);bad(()->inspectFixture(file,zip(new String[]{"library.txt","libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),shortElf})));}
            bad(()->inspectFixture(file,Arrays.copyOf(valid,valid.length-1)));
            byte[] duplicateSelector=zip(new String[]{"library.txt","librarz.txt","libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),"fixture".getBytes("US-ASCII"),elf()});
            bad(()->inspectFixture(file,rename(duplicateSelector,"librarz.txt","library.txt")));
            byte[] duplicateLibrary=zip(new String[]{"library.txt","libfixture.so","libfixturf.so"},new byte[][]{"fixture".getBytes("US-ASCII"),elf(),elf()});
            bad(()->inspectFixture(file,rename(duplicateLibrary,"libfixturf.so","libfixture.so")));
            for(String path:Arrays.asList("./library.txt","/library.txt","a//b","a\\b","a\nb"))bad(()->inspectFixture(file,zip(new String[]{"library.txt",path,"libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),new byte[0],elf()})));
            bad(()->inspectFixture(file,zip(new String[]{"library.txt","libfixture.so"},new byte[][]{new byte[129],elf()})));
            bad(()->inspectFixture(file,zip(new String[]{"library.txt","libfixture.so"},new byte[][]{"fixture".getBytes("US-ASCII"),new byte[LIBRARY_MAX+1]})));
            ByteArrayOutputStream stored=new ByteArrayOutputStream();
            try(ZipOutputStream z=new ZipOutputStream(stored)){
                for(String name:Arrays.asList("library.txt","libfixture.so")){byte[] v=name.equals("library.txt")?"fixture".getBytes("US-ASCII"):elf();
                    CRC32 c=new CRC32();c.update(v);ZipEntry e=new ZipEntry(name);e.setMethod(ZipEntry.STORED);e.setSize(v.length);e.setCrc(c.getValue());z.putNextEntry(e);z.write(v);z.closeEntry();}
            }
            byte[] wrongCrc=stored.toByteArray();int changed=0;
            for(int i=0;i<wrongCrc.length-128;i++)if(wrongCrc[i]==127&&wrongCrc[i+1]=='E'&&wrongCrc[i+2]=='L'&&wrongCrc[i+3]=='F'){wrongCrc[i+127]^=1;changed++;}
            check(changed==1);bad(()->inspectFixture(file,wrongCrc));
            if(args.length!=0){
                if(args.length!=2 || !args[1].matches("[a-f0-9]{64}"))throw new AssertionError();
                byte[] actual=Files.readAllBytes(Paths.get(args[0]));StringBuilder hex=new StringBuilder();for(byte b:sha(actual))hex.append(String.format(Locale.ROOT,"%02x",b&255));
                check(hex.toString().equals(args[1]));Materials real=inspect(new File(args[0]));check(real.clonedLibraryBytes().length>64);
                System.out.println("real_vendor_apk_readonly_passed");
            }
            System.out.println("vm_native_artifact_selfcheck_passed rejections="+rejected);
        }finally{Files.deleteIfExists(file);Files.deleteIfExists(dir);}
    }
}
