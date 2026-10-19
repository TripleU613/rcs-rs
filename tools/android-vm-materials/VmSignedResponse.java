/* SPDX-FileCopyrightText: 2016 microG Project Team
 * SPDX-FileCopyrightText: 2021 microG Project Team
 * SPDX-FileCopyrightText: 2026 rcs-rs contributors
 * SPDX-License-Identifier: Apache-2.0
 * Source comparison: microG ec206605ab97ada8369dade98ce822880f716033.
 * Independent bounded implementation of droidguard.proto and SignatureVerifier.kt
 * semantics. Signature validation does not establish APK-signer or server admission.
 */
package org.rcsrs.standalonecheckin;
import java.io.*;
import java.security.*;
import java.util.*;
public final class VmSignedResponse {
    /** The caller supplies its reviewed production trust anchor; no fallback key exists. */
    public static DroidGuardWire.Response verifyAndDecode(byte[] envelope,byte[] trustedRsaSpki) throws IOException {
        DroidGuardWire.Reader in=new DroidGuardWire.Reader(envelope,DroidGuardWire.RESPONSE_MAX);
        byte[] data=null,signature=null;
        while(in.more()) {
            int tag=in.tag(),field=tag>>>3,wire=tag&7;
            if(field==1 || field==2) {
                if(wire!=2)throw new IOException();
                if(field==1){if(data!=null)throw new IOException();data=in.data(DroidGuardWire.RESPONSE_MAX);}
                else {if(signature!=null)throw new IOException();signature=in.data(16384);}
            } else in.skipWire(wire);
        }
        if(data==null || data.length==0 || signature==null || signature.length==0 ||
            trustedRsaSpki==null || trustedRsaSpki.length==0 || trustedRsaSpki.length>16384)throw new IOException();
        try {
            PublicKey key=KeyFactory.getInstance("RSA").generatePublic(new java.security.spec.X509EncodedKeySpec(trustedRsaSpki));
            Signature verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(key);verifier.update(data);
            if(!verifier.verify(signature))throw new IOException();
        }catch(GeneralSecurityException | IllegalArgumentException invalid){throw new IOException();}
        // This is the only inner decoder entry point: signature passed over exact wire data first.
        return DroidGuardWire.decodeVerified(data);
    }
    // Offline synthetic fixtures only. No production trust key or payload is embedded.
    private interface Trial { void run() throws Exception; }
    private static int rejected;
    private static void bad(Trial test) throws Exception {
        try {test.run();} catch(IOException expected){rejected++;return;}
        throw new AssertionError("accepted invalid synthetic input");
    }
    private static void check(boolean b){if(!b)throw new AssertionError();}
    private static void var(ByteArrayOutputStream out,long x){do{int b=(int)x&127;x>>>=7;out.write(x==0?b:b|128);}while(x!=0);}
    private static void num(ByteArrayOutputStream out,int n,long x){var(out,(long)n<<3);var(out,x);}
    private static void field(ByteArrayOutputStream out,int n,byte[] value)throws IOException{var(out,((long)n<<3)|2);var(out,value.length);out.write(value);}
    private static byte[] signed(byte[] data,KeyPair key)throws Exception{
        Signature sig=Signature.getInstance("SHA256withRSA");sig.initSign(key.getPrivate());sig.update(data);
        ByteArrayOutputStream out=new ByteArrayOutputStream();field(out,1,data);field(out,2,sig.sign());return out.toByteArray();
    }
    private static void inspectRequest(byte[] request,Boolean account)throws Exception{
        DroidGuardWire.Reader in=new DroidGuardWire.Reader(request,DroidGuardWire.REQUEST_MAX);
        Set<Integer> fields=new HashSet<>();
        while(in.more()){
            int tag=in.tag(),f=tag>>>3,w=tag&7;check(fields.add(f));
            if(f==1){
                check(w==2);DroidGuardWire.Reader usage=new DroidGuardWire.Reader(in.data(4096),4096);
                check(usage.tag()==10 && usage.text(1024).equals("synthetic_flow"));
                check(usage.tag()==18 && usage.text(1024).equals("org.rcsrs.synthetic") && !usage.more());
            }else if(f==2){
                check(w==2);DroidGuardWire.Reader pair=new DroidGuardWire.Reader(in.data(16384),16384);
                check(pair.tag()==10 && pair.text(128).equals("MODEL"));
                check(pair.tag()==18 && pair.text(8192).equals("synthetic-\u03bb") && !pair.more());
            }else if(f==3)check(w==2 && in.text(256).equals("20.47.14"));
            else if(f==6)check(w==0 && account!=null && in.bool()==account);
            else if(f==8)check(w==0 && in.bool());
            else if(f==13)check(w==0 && in.int32()==204714000);
            else if(f==14)check(w==2 && in.text(256).equals("synthetic-arch"));
            else throw new AssertionError("unexpected request field");
        }
        Set<Integer> expected=new HashSet<>(Arrays.asList(1,2,3,8,13,14));if(account!=null)expected.add(6);
        check(fields.equals(expected));
    }
    public static void main(String[] args)throws Exception{
        Map<String,String> info=new HashMap<>();info.put("MODEL","synthetic-\u03bb");
        byte[] request=DroidGuardWire.encodeRequest("synthetic_flow","org.rcsrs.synthetic",info,"20.47.14","synthetic-arch",null);
        inspectRequest(request,null);
        byte[] formatted=DroidGuardWire.encodeRequest("synthetic_flow","org.rcsrs.synthetic",info,"20.47.14 (000400-{{cl}})","synthetic-arch",null);
        check(formatted.length>request.length);
        inspectRequest(DroidGuardWire.encodeRequest("synthetic_flow","org.rcsrs.synthetic",info,"20.47.14","synthetic-arch",true),true);
        inspectRequest(DroidGuardWire.encodeRequest("synthetic_flow","org.rcsrs.synthetic",info,"20.47.14","synthetic-arch",false),false);
        bad(()->DroidGuardWire.encodeRequest("f","invalidpackage",info,"v","x",null));
        bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",null,"v","x",null));
        info.put(null,"x");bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",info,"v","x",null));info.remove(null);
        Map<String,String> huge=new HashMap<>();char[] many=new char[8192];Arrays.fill(many,'x');
        for(String k:Arrays.asList("BOARD","BOOTLOADER","BRAND","CPU_ABI","CPU_ABI2","SUPPORTED_ABIS","DEVICE","DISPLAY",
            "FINGERPRINT","HARDWARE","HOST","ID","MANUFACTURER","MODEL","PRODUCT","TAGS"))huge.put(k,new String(many));
        bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",huge,"v","x",null));
        info.put("MODEL",new String(new char[4097]).replace('\0','\u03bb'));
        bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",info,"v","x",null));
        info.put("MODEL","synthetic-\u03bb");
        bad(()->DroidGuardWire.encodeRequest("flow with space","org.rcsrs.synthetic",info,"v","x",null));
        bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",info,"20.47.14\n(type)","x",null));
        bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",info,"v","arch with space",null));
        bad(()->DroidGuardWire.encodeRequest("bad\nflow","org.rcsrs.synthetic",info,"20.47.14","x",null));
        info.put("PROFILE_OVERRIDE","bad");bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",info,"v","x",null));info.remove("PROFILE_OVERRIDE");
        info.put("MODEL","\ud800");bad(()->DroidGuardWire.encodeRequest("f","org.rcsrs.synthetic",info,"v","x",null));info.put("MODEL","synthetic");
        KeyPairGenerator gen=KeyPairGenerator.getInstance("RSA");gen.initialize(2048);
        KeyPair key=gen.generateKeyPair(),wrong=gen.generateKeyPair();byte[] anchor=key.getPublic().getEncoded();
        ByteArrayOutputStream p=new ByteArrayOutputStream();field(p,1,new byte[]{1,2});field(p,3,new byte[]{3});
        num(p,4,-1);field(p,5,new byte[]{4,5});num(p,6,0);num(p,7,Integer.MIN_VALUE);num(p,8,Integer.MAX_VALUE);field(p,9,new byte[0]);
        num(p,100,42);num(p,100,43);field(p,101,new byte[]{1});field(p,101,new byte[]{2});
        for(int i=0;i<2;i++) {var(p,(102L<<3)|1);p.write(new byte[8]);var(p,(103L<<3)|5);p.write(new byte[4]);}
        byte[] payload=p.toByteArray(),envelope=signed(payload,key);
        DroidGuardWire.Response r=verifyAndDecode(envelope,anchor);
        check(r.expirySecs==-1 && r.minWait==Integer.MIN_VALUE && r.maxWait==Integer.MAX_VALUE && !r.save);
        check(Arrays.equals(r.byteCode,new byte[]{1,2}) && r.extra!=null && r.extra.length==0 && r.vmUrl==null);
        byte[] broken=envelope.clone();broken[broken.length-1]^=1;bad(()->verifyAndDecode(broken,anchor));
        bad(()->verifyAndDecode(envelope,wrong.getPublic().getEncoded()));bad(()->verifyAndDecode(envelope,new byte[]{1,2}));
        bad(()->verifyAndDecode(new byte[0],anchor));
        ByteArrayOutputStream unsigned=new ByteArrayOutputStream();field(unsigned,1,payload);bad(()->verifyAndDecode(unsigned.toByteArray(),anchor));
        ByteArrayOutputStream absent=new ByteArrayOutputStream();field(absent,2,new byte[]{1});bad(()->verifyAndDecode(absent.toByteArray(),anchor));
        ByteArrayOutputStream duplicate=new ByteArrayOutputStream();duplicate.write(envelope);field(duplicate,1,payload);bad(()->verifyAndDecode(duplicate.toByteArray(),anchor));
        ByteArrayOutputStream repeated=new ByteArrayOutputStream();repeated.write(envelope);num(repeated,100,1);num(repeated,100,2);check(verifyAndDecode(repeated.toByteArray(),anchor).content.length==2);
        for(int i=0;i<envelope.length;i++){final int n=i;bad(()->verifyAndDecode(Arrays.copyOf(envelope,n),anchor));}
        ByteArrayOutputStream dupBody=new ByteArrayOutputStream();dupBody.write(payload);field(dupBody,5,new byte[]{9});bad(()->verifyAndDecode(signed(dupBody.toByteArray(),key),anchor));
        bad(()->verifyAndDecode(signed(new byte[]{8,1},key),anchor));
        bad(()->verifyAndDecode(new byte[]{8,1},anchor));
        bad(()->verifyAndDecode(new byte[]{10,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,2},anchor));
        bad(()->verifyAndDecode(signed(new byte[]{0},key),anchor));
        bad(()->verifyAndDecode(signed(new byte[]{10,(byte)128,0},key),anchor));
        bad(()->verifyAndDecode(signed(new byte[]{11},key),anchor));
        bad(()->verifyAndDecode(signed(new byte[]{14},key),anchor));
        bad(()->verifyAndDecode(signed(new byte[]{10,(byte)255,(byte)255,(byte)255,(byte)255,127},key),anchor));
        bad(()->verifyAndDecode(signed(new byte[]{18,1,(byte)255},key),anchor));
        ByteArrayOutputStream badInt=new ByteArrayOutputStream();num(badInt,4,0x100000000L);bad(()->verifyAndDecode(signed(badInt.toByteArray(),key),anchor));
        ByteArrayOutputStream bool=new ByteArrayOutputStream();num(bool,6,2);bad(()->verifyAndDecode(signed(bool.toByteArray(),key),anchor));
        ByteArrayOutputStream bigCode=new ByteArrayOutputStream();field(bigCode,1,new byte[DroidGuardWire.BYTECODE_MAX+1]);bad(()->verifyAndDecode(signed(bigCode.toByteArray(),key),anchor));
        ByteArrayOutputStream bigExtra=new ByteArrayOutputStream();field(bigExtra,9,new byte[DroidGuardWire.EXTRA_MAX+1]);bad(()->verifyAndDecode(signed(bigExtra.toByteArray(),key),anchor));
        ByteArrayOutputStream bigApk=new ByteArrayOutputStream();field(bigApk,5,new byte[DroidGuardWire.APK_MAX+1]);bad(()->verifyAndDecode(signed(bigApk.toByteArray(),key),anchor));
        bad(()->verifyAndDecode(new byte[DroidGuardWire.RESPONSE_MAX+1],anchor));
        bad(()->verifyAndDecode(signed(new byte[0],key),anchor));
        ByteArrayOutputStream metadata=new ByteArrayOutputStream();num(metadata,4,0);
        DroidGuardWire.Response empty=verifyAndDecode(signed(metadata.toByteArray(),key),anchor);
        check(empty.content==null&&empty.expirySecs==0&&empty.save==null);
        System.out.println("vm_wire_selfcheck_passed rejections="+rejected);
    }
}
