/* Copyright (C) 2026 rcs-rs contributors. SPDX-License-Identifier: Apache-2.0
 * Own-app signed-VM cache record. TTL is relative signed expirySecs, not min/maxWait.
 * Stricter local reuse policy: same boot, both monotonic/wall clocks nondecreasing
 * and strictly before expiry. Checksum detects corruption, NOT root/owner tampering.
 * No filesystem, HTTP, deletion, refetch, execution or retry behavior belongs here.
 */
package org.rcsrs.standalonecheckin;
import java.io.*;
import java.security.*;
import java.util.*;
public final class VmMaterialCache {
    public static final int RECORD_MAX=DroidGuardWire.RESPONSE_MAX+96;
    public enum Reason {READY,NOT_SAVED,NO_POSITIVE_TTL,MISSING_INLINE_MATERIAL,CONTEXT_MISMATCH,BOOT_MISMATCH,CLOCK_INVALID,EXPIRED}
    public static final class Entry {
        public final DroidGuardWire.Response response;
        private final byte[] envelope,context;
        private final long wall,elapsed;private final int boot;
        private Entry(DroidGuardWire.Response response,byte[] wire,byte[] context,long wall,long elapsed,int boot){
            this.response=response;this.envelope=wire.clone();this.context=context.clone();this.wall=wall;this.elapsed=elapsed;this.boot=boot;
        }
    }
    public static final class Result {
        public final Reason reason;public final Entry entry;
        /** Signed relative expirySecs, including absent/zero/negative; not a reuse grant. */
        public final Integer validitySeconds;
        private Result(Reason reason,Entry entry,Integer validitySeconds){this.reason=reason;this.entry=entry;this.validitySeconds=validitySeconds;}
    }
    private static final int MAGIC=0x52564d31,VERSION=1;
    private static Result result(Reason reason,Entry entry,DroidGuardWire.Response verified){return new Result(reason,entry,verified.expirySecs);}
    private static void context(byte[] digest)throws IOException{if(digest==null || digest.length!=32)throw new IOException();}
    private static Reason cachePolicy(DroidGuardWire.Response response){
        // Original NetworkHandleProxyFactory: response.save != false; absence permits saving.
        if(Boolean.FALSE.equals(response.save))return Reason.NOT_SAVED;
        if(response.expirySecs==null || response.expirySecs<=0)return Reason.NO_POSITIVE_TTL;
        if(response.content==null || response.content.length==0 || response.byteCode==null || response.byteCode.length==0)return Reason.MISSING_INLINE_MATERIAL;
        return Reason.READY;
    }
    private static Reason clocks(DroidGuardWire.Response response,long wall,long elapsed,int receiptBoot,long nowWall,long nowElapsed,int nowBoot){
        if(wall<=0 || elapsed<0 || receiptBoot<0 || nowWall<=0 || nowElapsed<0 || nowBoot<0)return Reason.CLOCK_INVALID;
        if(receiptBoot!=nowBoot)return Reason.BOOT_MISMATCH;
        if(nowWall<wall || nowElapsed<elapsed)return Reason.CLOCK_INVALID;
        try{
            long ttl=Math.multiplyExact((long)response.expirySecs,1000L);
            long wallEnd=Math.addExact(wall,ttl),elapsedEnd=Math.addExact(elapsed,ttl);
            if(nowWall>=wallEnd || nowElapsed>=elapsedEnd)return Reason.EXPIRED;
        }catch(ArithmeticException overflow){return Reason.CLOCK_INVALID;}
        return Reason.READY;
    }
    public static Result capture(byte[] wire,byte[] anchor,byte[] context,long wall,long elapsed,int boot)throws IOException{
        context(context);
        if(wire==null || wire.length==0 || wire.length>DroidGuardWire.RESPONSE_MAX)throw new IOException();
        byte[] exact=wire.clone(),binding=context.clone();
        DroidGuardWire.Response verified=VmSignedResponse.verifyAndDecode(exact,anchor);
        Reason policy=cachePolicy(verified);if(policy!=Reason.READY)return result(policy,null,verified);
        policy=clocks(verified,wall,elapsed,boot,wall,elapsed,boot);
        return result(policy,policy==Reason.READY?new Entry(verified,exact,binding,wall,elapsed,boot):null,verified);
    }
    private static byte[] hash(byte[] data)throws IOException{
        try{return MessageDigest.getInstance("SHA-256").digest(data);}catch(GeneralSecurityException invalid){throw new IOException();}
    }
    /** Only an own-app protected destination is permitted; parent owns atomic publication/fsync. */
    public static void writePrivate(OutputStream destination,Entry entry)throws IOException{
        if(destination==null || entry==null || entry.envelope.length==0 || entry.envelope.length>DroidGuardWire.RESPONSE_MAX)throw new IOException();
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeInt(MAGIC);out.writeInt(VERSION);out.write(entry.context);out.writeLong(entry.wall);out.writeLong(entry.elapsed);
        out.writeInt(entry.boot);out.writeInt(entry.envelope.length);out.write(entry.envelope);out.flush();byte[] body=bytes.toByteArray();
        if(body.length+32>RECORD_MAX)throw new IOException();destination.write(body);destination.write(hash(body));destination.flush();
    }
    public static Result readPrivate(InputStream source,byte[] anchor,byte[] expectedContext,long nowWall,long nowElapsed,int boot)throws IOException{
        context(expectedContext);byte[] expected=expectedContext.clone();if(source==null)throw new IOException();
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();byte[] block=new byte[8192];int n;
        while((n=source.read(block))!=-1){if(n<=0 || n>RECORD_MAX-bytes.size())throw new IOException();bytes.write(block,0,n);}
        byte[] record=bytes.toByteArray();if(record.length<=96)throw new IOException();
        byte[] body=Arrays.copyOf(record,record.length-32);
        if(!MessageDigest.isEqual(hash(body),Arrays.copyOfRange(record,body.length,record.length)))throw new IOException();
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(body));
        if(in.readInt()!=MAGIC || in.readInt()!=VERSION)throw new IOException();
        byte[] binding=new byte[32];in.readFully(binding);long wall=in.readLong(),elapsed=in.readLong();int oldBoot=in.readInt(),length=in.readInt();
        if(length<=0 || length>DroidGuardWire.RESPONSE_MAX || length!=in.available())throw new IOException();
        byte[] wire=new byte[length];in.readFully(wire);if(in.available()!=0)throw new IOException();
        // Outer checksum/metadata are not an authentication mechanism; RSA is authoritative.
        DroidGuardWire.Response verified=VmSignedResponse.verifyAndDecode(wire,anchor);
        Reason policy=cachePolicy(verified);if(policy!=Reason.READY)return result(policy,null,verified);
        if(!MessageDigest.isEqual(binding,expected))return result(Reason.CONTEXT_MISMATCH,null,verified);
        policy=clocks(verified,wall,elapsed,oldBoot,nowWall,nowElapsed,boot);
        return result(policy,policy==Reason.READY?new Entry(verified,wire,binding,wall,elapsed,oldBoot):null,verified);
    }
    private interface Trial{void run()throws Exception;}
    private static int rejected;
    private static void bad(Trial test)throws Exception{try{test.run();}catch(IOException expected){rejected++;return;}throw new AssertionError();}
    private static void check(boolean b){if(!b)throw new AssertionError();}
    private static void reason(Result r,Reason expected){check(r.reason==expected && ((expected==Reason.READY)==(r.entry!=null)));}
    private static void var(ByteArrayOutputStream out,long value){do{int b=(int)value&127;value>>>=7;out.write(value==0?b:b|128);}while(value!=0);}
    private static void number(ByteArrayOutputStream out,int field,long value){var(out,(long)field<<3);var(out,value);}
    private static void bytes(ByteArrayOutputStream out,int field,byte[] value)throws IOException{var(out,((long)field<<3)|2);var(out,value.length);out.write(value);}
    private static byte[] fixture(KeyPair key,Integer ttl,Boolean save,byte[] code,byte[] apk)throws Exception{
        ByteArrayOutputStream data=new ByteArrayOutputStream();if(code!=null)bytes(data,1,code);if(ttl!=null)number(data,4,ttl);
        if(apk!=null)bytes(data,5,apk);if(save!=null)number(data,6,save?1:0);number(data,7,-1);number(data,8,Integer.MAX_VALUE);
        Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(key.getPrivate());signature.update(data.toByteArray());
        ByteArrayOutputStream envelope=new ByteArrayOutputStream();bytes(envelope,1,data.toByteArray());bytes(envelope,2,signature.sign());return envelope.toByteArray();
    }
    private static byte[] reseal(byte[] record)throws IOException{
        byte[] value=record.clone(),body=Arrays.copyOf(value,value.length-32);
        System.arraycopy(hash(body),0,value,value.length-32,32);return value;
    }
    public static void main(String[] ignored)throws Exception{
        KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);KeyPair key=g.generateKeyPair(),wrong=g.generateKeyPair();
        byte[] anchor=key.getPublic().getEncoded(),binding=new byte[32];Arrays.fill(binding,(byte)7);
        byte[] wire=fixture(key,60,true,new byte[]{1},new byte[]{2});
        Result original=capture(wire,anchor,binding,1000000,20000,7);reason(original,Reason.READY);check(original.validitySeconds==60);
        check(original.entry.response.minWait==-1 && original.entry.response.maxWait==Integer.MAX_VALUE);
        ByteArrayOutputStream out=new ByteArrayOutputStream();writePrivate(out,original.entry);byte[] record=out.toByteArray();
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,1000001,20001,7),Reason.READY);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,1059999,79999,7),Reason.READY);
        Result expired=readPrivate(new ByteArrayInputStream(record),anchor,binding,1060000,20001,7);
        reason(expired,Reason.EXPIRED);check(expired.validitySeconds==60 && expired.entry==null);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,1000001,80000,7),Reason.EXPIRED);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,999999,20001,7),Reason.CLOCK_INVALID);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,1000001,19999,7),Reason.CLOCK_INVALID);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,1000001,20001,8),Reason.BOOT_MISMATCH);
        byte[] different=binding.clone();different[0]^=1;
        reason(readPrivate(new ByteArrayInputStream(record),anchor,different,1000001,20001,7),Reason.CONTEXT_MISMATCH);
        Result notSaved=capture(fixture(key,60,false,new byte[]{1},new byte[]{2}),anchor,binding,1,0,0);
        reason(notSaved,Reason.NOT_SAVED);check(notSaved.validitySeconds==60 && notSaved.entry==null);
        Result noTtl=capture(fixture(key,null,true,new byte[]{1},new byte[]{2}),anchor,binding,1,0,0);
        reason(noTtl,Reason.NO_POSITIVE_TTL);check(noTtl.validitySeconds==null);
        Result negativeTtl=capture(fixture(key,-1,true,new byte[]{1},new byte[]{2}),anchor,binding,1,0,0);
        reason(negativeTtl,Reason.NO_POSITIVE_TTL);check(negativeTtl.validitySeconds==-1);
        reason(capture(fixture(key,60,null,new byte[]{1},new byte[]{2}),anchor,binding,1,0,0),Reason.READY);
        for(Integer ttl:Arrays.asList(null,0,-1))reason(capture(fixture(key,ttl,true,new byte[]{1},new byte[]{2}),anchor,binding,1,0,0),Reason.NO_POSITIVE_TTL);
        for(byte[] empty:Arrays.asList(null,new byte[0])){
            reason(capture(fixture(key,60,true,empty,new byte[]{2}),anchor,binding,1,0,0),Reason.MISSING_INLINE_MATERIAL);
            reason(capture(fixture(key,60,true,new byte[]{1},empty),anchor,binding,1,0,0),Reason.MISSING_INLINE_MATERIAL);
        }
        reason(capture(wire,anchor,binding,Long.MAX_VALUE-1,0,0),Reason.CLOCK_INVALID);
        reason(capture(wire,anchor,binding,1,Long.MAX_VALUE-1,0),Reason.CLOCK_INVALID);
        reason(capture(wire,anchor,binding,0,0,0),Reason.CLOCK_INVALID);
        reason(capture(wire,anchor,binding,1,-1,0),Reason.CLOCK_INVALID);
        reason(capture(wire,anchor,binding,1,0,-1),Reason.CLOCK_INVALID);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,-1,20001,7),Reason.CLOCK_INVALID);
        reason(readPrivate(new ByteArrayInputStream(record),anchor,binding,1000001,-1,7),Reason.CLOCK_INVALID);
        bad(()->capture(wire,wrong.getPublic().getEncoded(),binding,1,0,0));
        bad(()->capture(wire,anchor,new byte[31],1,0,0));
        byte[] broken=wire.clone();broken[broken.length-1]^=1;bad(()->capture(broken,anchor,binding,1,0,0));
        for(int i=0;i<record.length;i++){final int n=i;bad(()->readPrivate(new ByteArrayInputStream(Arrays.copyOf(record,n)),anchor,binding,1000001,20001,7));}
        for(int i=0;i<record.length;i++){byte[] changed=record.clone();changed[i]^=1;bad(()->readPrivate(new ByteArrayInputStream(changed),anchor,binding,1000001,20001,7));}
        bad(()->readPrivate(new ByteArrayInputStream(Arrays.copyOf(record,record.length+1)),anchor,binding,1000001,20001,7));
        bad(()->readPrivate(new ByteArrayInputStream(new byte[RECORD_MAX+1]),anchor,binding,1000001,20001,7));
        // Recomputed checksum cannot substitute for RSA authentication or fixed record shape.
        for(int offset:new int[]{0,4,60}){
            byte[] changed=record.clone();changed[offset]^=1;byte[] altered=reseal(changed);
            bad(()->readPrivate(new ByteArrayInputStream(altered),anchor,binding,1000001,20001,7));
        }
        byte[] changedSignature=record.clone();changedSignature[record.length-33]^=1;
        bad(()->readPrivate(new ByteArrayInputStream(reseal(changedSignature)),anchor,binding,1000001,20001,7));
        bad(()->readPrivate(new ByteArrayInputStream(record),wrong.getPublic().getEncoded(),binding,1000001,20001,7));
        byte[] plus=reseal(Arrays.copyOf(record,record.length+1));
        bad(()->readPrivate(new ByteArrayInputStream(plus),anchor,binding,1000001,20001,7));
        byte[] negativeWall=record.clone();Arrays.fill(negativeWall,40,48,(byte)255);
        reason(readPrivate(new ByteArrayInputStream(reseal(negativeWall)),anchor,binding,1000001,20001,7),Reason.CLOCK_INVALID);
        byte[] changedContext=record.clone();changedContext[8]^=1;
        reason(readPrivate(new ByteArrayInputStream(reseal(changedContext)),anchor,binding,1000001,20001,7),Reason.CONTEXT_MISMATCH);
        byte[] changedBoot=record.clone();changedBoot[59]^=1;
        reason(readPrivate(new ByteArrayInputStream(reseal(changedBoot)),anchor,binding,1000001,20001,7),Reason.BOOT_MISMATCH);
        byte[] negativeElapsed=record.clone();Arrays.fill(negativeElapsed,48,56,(byte)255);
        reason(readPrivate(new ByteArrayInputStream(reseal(negativeElapsed)),anchor,binding,1000001,20001,7),Reason.CLOCK_INVALID);
        for(Integer ttl:Arrays.asList(0,-1)){
            byte[] oldWire=fixture(key,ttl,true,new byte[]{1},new byte[]{2});ByteArrayOutputStream old=new ByteArrayOutputStream();
            writePrivate(old,new Entry(VmSignedResponse.verifyAndDecode(oldWire,anchor),oldWire,binding,1,0,0));
            reason(readPrivate(new ByteArrayInputStream(old.toByteArray()),anchor,binding,2,1,0),Reason.NO_POSITIVE_TTL);
        }
        byte[] omitted=fixture(key,60,null,new byte[]{1},new byte[]{2});Result permissive=capture(omitted,anchor,binding,1,0,0);
        ByteArrayOutputStream omittedStore=new ByteArrayOutputStream();writePrivate(omittedStore,permissive.entry);
        Result omittedReload=readPrivate(new ByteArrayInputStream(omittedStore.toByteArray()),anchor,binding,2,1,0);
        reason(omittedReload,Reason.READY);check(omittedReload.entry.response.save==null);
        byte[] retainedWire=wire.clone(),retainedContext=binding.clone();Result immutable=capture(retainedWire,anchor,retainedContext,1,0,0);
        Arrays.fill(retainedWire,(byte)0);Arrays.fill(retainedContext,(byte)0);
        ByteArrayOutputStream immutableStore=new ByteArrayOutputStream();writePrivate(immutableStore,immutable.entry);
        reason(readPrivate(new ByteArrayInputStream(immutableStore.toByteArray()),anchor,binding,2,1,0),Reason.READY);
        bad(()->readPrivate(null,anchor,binding,2,1,0));
        bad(()->readPrivate(new InputStream(){public int read(){return 0;}public int read(byte[] b,int o,int n){return 0;}},anchor,binding,2,1,0));
        bad(()->writePrivate(new ByteArrayOutputStream(),null));
        System.out.println("vm_material_cache_selfcheck_passed rejections="+rejected);
    }
}
