/* SPDX-FileCopyrightText: 2016 microG Project Team
 * SPDX-FileCopyrightText: 2026 rcs-rs contributors
 * SPDX-License-Identifier: Apache-2.0
 * Source comparison: microG ec206605ab97ada8369dade98ce822880f716033.
 * Modified, independently implemented bounded codec derived from pinned droidguard.proto;
 * no profile, server/API key, trust-anchor literal, or cached VM copied.
 */
package org.rcsrs.standalonecheckin;
import java.io.*;
import java.util.*;
import java.nio.*;
import java.nio.charset.*;
public final class DroidGuardWire {
    public static final int REQUEST_MAX=128*1024, RESPONSE_MAX=8*1024*1024;
    public static final int BYTECODE_MAX=1024*1024, EXTRA_MAX=1024*1024, APK_MAX=6*1024*1024;
    public static final int BASE_VERSION_CODE=204714000;
    public static final class Response {
        public final byte[] byteCode,content,checksum,extra;
        public final String vmUrl;
        public final Integer expirySecs,minWait,maxWait;
        public final Boolean save;
        Response(byte[] b,byte[] c,byte[] h,byte[] x,String url,Integer e,Integer min,Integer max,Boolean s) {
            byteCode=b;content=c;checksum=h;extra=x;vmUrl=url;expirySecs=e;minWait=min;maxWait=max;save=s;
        }
    }
    private static final Set<String> INFO_KEYS=new HashSet<>(Arrays.asList(
        "BOARD","BOOTLOADER","BRAND","CPU_ABI","CPU_ABI2","SUPPORTED_ABIS","DEVICE","DISPLAY",
        "FINGERPRINT","HARDWARE","HOST","ID","MANUFACTURER","MODEL","PRODUCT","RADIO","SERIAL",
        "TAGS","TIME","TYPE","USER","VERSION.CODENAME","VERSION.INCREMENTAL","VERSION.RELEASE",
        "VERSION.SDK","VERSION.SDK_INT"));
    public static byte[] encodeRequest(String flow,String ownPackage,Map<String,String> actualBuildInfo,
                                      String versionName,String arch,Boolean visibleAccount) throws IOException {
        ascii(flow,1024); ascii(ownPackage,1024); versionAscii(versionName); ascii(arch,256);
        if(!ownPackage.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")) throw new IOException();
        if(actualBuildInfo==null || actualBuildInfo.size()>INFO_KEYS.size()) throw new IOException();
        for(String key:actualBuildInfo.keySet())if(!INFO_KEYS.contains(key))throw new IOException();
        Writer usage=new Writer(REQUEST_MAX); usage.text(1,flow,1024);usage.text(2,ownPackage,1024);
        Writer out=new Writer(REQUEST_MAX);out.data(1,usage.bytes());
        for(Map.Entry<String,String> entry:new TreeMap<>(actualBuildInfo).entrySet()) {
            if(!INFO_KEYS.contains(entry.getKey())) throw new IOException();
            Writer pair=new Writer(REQUEST_MAX);pair.text(1,entry.getKey(),128);pair.text(2,entry.getValue(),8192);
            out.data(2,pair.bytes());
        }
        out.text(3,versionName,256);
        if(visibleAccount!=null) out.number(6,visibleAccount?1:0);
        out.number(8,1);out.number(13,BASE_VERSION_CODE);out.text(14,arch,256);
        return out.bytes();
    }
    private static void ascii(String s,int cap)throws IOException {
        if(s==null || s.isEmpty() || s.length()>cap) throw new IOException();
        for(int i=0;i<s.length();i++) if(s.charAt(i)<33 || s.charAt(i)>126) throw new IOException();
    }
    private static void versionAscii(String s)throws IOException {
        if(s==null || s.isEmpty() || s.length()>256)throw new IOException();
        for(int i=0;i<s.length();i++)if(s.charAt(i)<32 || s.charAt(i)>126)throw new IOException();
    }
    static byte[] utf8(String text,int cap)throws IOException {
        if(text==null || text.length()>cap) throw new IOException();
        try {
            ByteBuffer b=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(text));
            if(b.remaining()>cap) throw new IOException();byte[] value=new byte[b.remaining()];b.get(value);return value;
        }catch(CharacterCodingException invalid){throw new IOException();}
    }
    static final class Writer {
        private final ByteArrayOutputStream out=new ByteArrayOutputStream(); private final int cap;
        Writer(int cap){this.cap=cap;}
        private void one(int b)throws IOException{if(out.size()>=cap)throw new IOException();out.write(b);}
        private void var(long x)throws IOException{do{int b=(int)x&127;x>>>=7;one(x==0?b:b|128);}while(x!=0);}
        void number(int n,long x)throws IOException{var((long)n<<3);var(x);}
        void data(int n,byte[] b)throws IOException{
            if(b==null || b.length>cap)throw new IOException();var(((long)n<<3)|2);var(b.length);
            if(b.length>cap-out.size())throw new IOException();out.write(b);
        }
        void text(int n,String value,int limit)throws IOException{data(n,utf8(value,limit));}
        byte[] bytes(){return out.toByteArray();}
    }
    static final class Reader {
        private final byte[] bytes; int offset;
        Reader(byte[] bytes,int limit)throws IOException{if(bytes==null || bytes.length>limit)throw new IOException();this.bytes=bytes;}
        boolean more(){return offset<bytes.length;}
        long var()throws IOException{
            long value=0;
            for(int i=0;i<10;i++) {
                if(!more())throw new IOException();int b=bytes[offset++]&255;
                if(i==9 && (b&254)!=0)throw new IOException();value|=((long)b&127)<<(i*7);
                if((b&128)==0){if(i>0 && (b&127)==0)throw new IOException();return value;}
            }
            throw new IOException();
        }
        int tag()throws IOException{
            long tag=var();if(tag<=0 || tag>0xffffffffL || (tag>>>3)==0)throw new IOException();return (int)tag;
        }
        void skip(long n)throws IOException{if(n<0 || n>bytes.length-offset)throw new IOException();offset+=(int)n;}
        byte[] data(int limit)throws IOException{
            long n=var();if(n<0 || n>limit || n>bytes.length-offset)throw new IOException();
            byte[] result=Arrays.copyOfRange(bytes,offset,offset+(int)n);offset+=(int)n;return result;
        }
        String text(int limit)throws IOException{
            try{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data(limit))).toString();}
            catch(CharacterCodingException invalid){throw new IOException();}
        }
        int int32()throws IOException{long n=var();if(n!=(long)(int)n)throw new IOException();return(int)n;}
        boolean bool()throws IOException{long n=var();if(n!=0 && n!=1)throw new IOException();return n==1;}
        void skipWire(int wire)throws IOException{
            switch(wire){case 0:var();break;case 1:skip(8);break;case 2:skip(var());break;case 5:skip(4);break;default:throw new IOException();}
        }
    }
    static Response decodeVerified(byte[] payload)throws IOException{
        Reader in=new Reader(payload,RESPONSE_MAX);Set<Integer> seen=new HashSet<>();
        byte[] bytecode=null,content=null,checksum=null,extra=null;String url=null;
        Integer expiry=null,min=null,max=null;Boolean save=null;
        while(in.more()) {
            int tag=in.tag(),field=tag>>>3,wire=tag&7;
            if(field<=9){
                if(!seen.add(field))throw new IOException();
                int expected=(field==4 || field==6 || field==7 || field==8)?0:2;
                if(wire!=expected)throw new IOException();
            }
            switch(field){
                case 1:bytecode=in.data(BYTECODE_MAX);break;
                case 2:url=in.text(8192);break;
                case 3:checksum=in.data(4096);break;
                case 4:expiry=in.int32();break;
                case 5:content=in.data(APK_MAX);break;
                case 6:save=in.bool();break;
                case 7:min=in.int32();break;
                case 8:max=in.int32();break;
                case 9:extra=in.data(EXTRA_MAX);break;
                default:in.skipWire(wire);
            }
        }
        return new Response(bytecode,content,checksum,extra,url,expiry,min,max,save);
    }
}
