/* Copyright (C) 2013-2017 microG Project Team
 * Copyright (C) 2026 rcs-rs contributors
 * SPDX-License-Identifier: Apache-2.0
 * Modified implementation: bounded independent wire codec derived from checkin.proto;
 * no microG profile, identifiers, account or request-builder implementation reused.
 */
package org.rcsrs.standalonecheckin;

import java.io.*;
import java.util.*;
import java.util.zip.*;

public final class CheckinWire {
    public static final int COMPRESSED_MAX = 65536, RESPONSE_MAX = 262144;
    public static final class Credentials {
        public final long id, token;
        Credentials(long id, long token) { this.id = id; this.token = token; }
    }
    public static byte[] request(Map<Integer,String> fields, int sdk, long buildTime) throws IOException {
        if (sdk<1 || buildTime< -1) throw new IOException();
        ByteArrayOutputStream build=new ByteArrayOutputStream();
        for (Map.Entry<Integer,String> entry: new TreeMap<>(fields).entrySet()) {
            int n=entry.getKey();
            if (!(n==1 || n==2 || n==3 || n==5 || n==9 || n==11 || n==12 || n==13)) throw new IOException();
            String value=entry.getValue();
            if (value==null || value.length()>4096) throw new IOException();
            data(build,n,value.getBytes("UTF-8"));
        }
        if(buildTime>=0) number(build,7,buildTime); number(build,10,sdk);
        ByteArrayOutputStream checkin=new ByteArrayOutputStream(); data(checkin,1,build.toByteArray());
        number(checkin,2,0);
        ByteArrayOutputStream out=new ByteArrayOutputStream(); number(out,2,0);
        data(out,4,checkin.toByteArray()); data(out,11,new byte[0]); number(out,14,3); number(out,20,0);
        return out.toByteArray();
    }
    private static void varint(OutputStream out,long value) throws IOException {
        do { int b=(int)(value & 127); value >>>=7; out.write(value==0?b:b|128); } while(value!=0);
    }
    private static void number(OutputStream out,int field,long value) throws IOException {
        varint(out,((long)field)<<3); varint(out,value);
    }
    private static void data(OutputStream out,int field,byte[] value) throws IOException {
        varint(out,(((long)field)<<3)|2); varint(out,value.length); out.write(value);
    }
    private static final class Reader {
        final byte[] bytes; int p;
        Reader(byte[] bytes) { this.bytes=bytes; }
        long var() throws IOException {
            long value=0;
            for(int i=0;i<10;i++) {
                if(p==bytes.length) throw new IOException(); int b=bytes[p++]&255;
                if(i==9 && (b&254)!=0) throw new IOException();
                value|=((long)(b&127))<<(7*i); if((b&128)==0) return value;
            }
            throw new IOException();
        }
        void skip(long count) throws IOException {
            if(count<0 || count>bytes.length-p) throw new IOException(); p+=(int)count;
        }
        long fixed() throws IOException {
            if(bytes.length-p<8) throw new IOException(); long v=0;
            for(int i=0;i<8;i++) v|=((long)bytes[p++]&255)<<(8*i); return v;
        }
    }
    public static Credentials parse(byte[] bytes) throws IOException {
        if(bytes==null || bytes.length>RESPONSE_MAX) throw new IOException();
        Reader r=new Reader(bytes); Set<Integer> seen=new HashSet<>(); long id=0,token=0;
        while(r.p<bytes.length) {
            long tag=r.var(); if(tag<=0 || tag>0xffffffffL) throw new IOException();
            int field=(int)(tag>>>3),wire=(int)(tag&7);
            if(field==0 || field>536870911) throw new IOException();
            // Unknown fields may be repeated in newer schemas; constrain only known singulars.
            if(field<=12 && field!=2 && field!=5 && field!=10 && !seen.add(field)) throw new IOException();
            int expected=(field==7 || field==8)?1:(field==1 || field==3 || field==6 || field==9)?0:
                (field==2 || field==4 || field==5 || field==10 || field==11 || field==12)?2:-1;
            if(expected>=0 && wire!=expected) throw new IOException();
            switch(wire) {
                case 0: r.var(); break;
                case 1: long value=r.fixed(); if(field==7) id=value; if(field==8) token=value; break;
                case 2: r.skip(r.var()); break;
                case 5: r.skip(4); break;
                default: throw new IOException();
            }
        }
        if(!seen.contains(7) || !seen.contains(8) || id==0 || token==0) throw new IOException();
        return new Credentials(id,token);
    }
    public static byte[] gzip(byte[] bytes) throws IOException {
        if(bytes==null || bytes.length>RESPONSE_MAX) throw new IOException();
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(GZIPOutputStream gzip=new GZIPOutputStream(out)){ gzip.write(bytes); }
        return out.toByteArray();
    }
    public static byte[] bounded(InputStream in,int cap) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] block=new byte[4096]; int n;
        while((n=in.read(block))!=-1) {
            if(n==0) throw new IOException(); if(n>cap-out.size()) throw new IOException(); out.write(block,0,n);
        }
        return out.toByteArray();
    }
    public static byte[] response(InputStream in, boolean compressed) throws IOException {
        byte[] wire=bounded(in,COMPRESSED_MAX);
        if(!compressed) return wire;
        try(GZIPInputStream gzip=new GZIPInputStream(new ByteArrayInputStream(wire))) {
            return bounded(gzip,RESPONSE_MAX);
        }
    }

    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    private interface Trial { void run() throws Exception; }
    private static int rejected;
    private static void bad(Trial trial) throws Exception {
        try { trial.run(); } catch (IOException expected) { rejected++; return; }
        throw new AssertionError("accepted malformed synthetic input");
    }
    private static byte[] credential(long id, long token) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(57); fixed(out,id); out.write(65); fixed(out,token); return out.toByteArray();
    }
    private static void fixed(OutputStream out,long value) throws IOException {
        for (int i=0;i<8;i++) out.write((int)(value >>> (8*i)) & 255);
    }
    public static void main(String[] args) throws Exception {
        byte[] fixture=credential(Long.MIN_VALUE+5, -1L);
        Credentials c=parse(fixture); check(c.id==Long.MIN_VALUE+5 && c.token==-1L);
        check(Arrays.equals(response(new ByteArrayInputStream(gzip(fixture)),true),fixture));
        check(Arrays.equals(response(new ByteArrayInputStream(fixture),false),fixture));
        for(int i=0;i<fixture.length;i++){ final int n=i; bad(()->parse(Arrays.copyOf(fixture,n))); }
        bad(()->parse(credential(0,1))); bad(()->parse(credential(1,0)));
        bad(()->parse(new byte[]{56,1,65,1,0,0,0,0,0,0,0}));
        ByteArrayOutputStream duplicate=new ByteArrayOutputStream(); duplicate.write(fixture); duplicate.write(fixture);
        bad(()->parse(duplicate.toByteArray())); bad(()->parse(new byte[]{0}));
        bad(()->parse(new byte[]{11})); bad(()->parse(new byte[]{14}));
        bad(()->parse(new byte[]{42,(byte)255,(byte)255,(byte)255,(byte)255,127}));
        bad(()->parse(new byte[RESPONSE_MAX+1]));
        bad(()->response(new ByteArrayInputStream(new byte[COMPRESSED_MAX+1]),false));
        ByteArrayOutputStream bomb=new ByteArrayOutputStream();
        try(GZIPOutputStream z=new GZIPOutputStream(bomb)){ z.write(new byte[RESPONSE_MAX+1]); }
        bad(()->response(new ByteArrayInputStream(bomb.toByteArray()),true));
        ByteArrayOutputStream unknown=new ByteArrayOutputStream(); unknown.write(fixture);
        number(unknown,100,42); number(unknown,100,43);
        data(unknown,101,new byte[]{1,2}); data(unknown,101,new byte[]{3});
        varint(unknown,(102L<<3)|1); fixed(unknown,Long.MIN_VALUE);
        varint(unknown,(102L<<3)|1); fixed(unknown,Long.MAX_VALUE);
        varint(unknown,(103L<<3)|5); unknown.write(new byte[]{1,2,3,4});
        varint(unknown,(103L<<3)|5); unknown.write(new byte[]{5,6,7,8});
        check(parse(unknown.toByteArray()).token==-1L);
        byte[] overflow=new byte[11]; Arrays.fill(overflow,(byte)255); overflow[0]=8;
        bad(()->parse(overflow));
        ByteArrayOutputStream wrong=new ByteArrayOutputStream(); wrong.write(fixture); wrong.write(8); wrong.write(1); wrong.write(8); wrong.write(0);
        bad(()->parse(wrong.toByteArray()));
        byte[] zipped=gzip(fixture); bad(()->response(new ByteArrayInputStream(Arrays.copyOf(zipped,zipped.length-1)),true));
        bad(()->response(new ByteArrayInputStream(new byte[]{1,2,3}),true));
        Map<Integer,String> build=new HashMap<>(); build.put(11,"synthetic-own-model");
        check(request(build,36,123).length>0);
        bad(()->request(build,0,123)); bad(()->request(build,36,-2));
        check(request(build,36,-1).length>0);
        Map<Integer,String> oversized=new HashMap<>(); oversized.put(11,new String(new char[4097]));
        bad(()->request(oversized,36,123));
        Reader root=new Reader(request(build,36,123)); Set<Integer> rootFields=new HashSet<>();
        while(root.p<root.bytes.length) {
            long tag=root.var(); int f=(int)(tag>>>3); rootFields.add(f);
            if((tag&7)==0) { long v=root.var(); check(v==(f==14?3:0)); }
            else { long n=root.var(); if(f==11) check(n==0); root.skip(n); }
        }
        check(rootFields.equals(new HashSet<>(Arrays.asList(2,4,11,14,20))));
        build.put(6,"forbidden-client-id"); bad(()->request(build,36,123));
        System.out.println("wire_selfcheck_passed rejections="+rejected);
    }
}
