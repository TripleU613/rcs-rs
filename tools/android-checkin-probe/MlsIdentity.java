/* Copyright (C) 2026 rcs-rs contributors. SPDX-License-Identifier: Apache-2.0
 * Independent own-app P256 identity codec and RFC9420 SignWithLabel proof.
 * OWN private storage uses PKCS8/SPKI; reference's scalar32 storage is not copied.
 * The private serialization must only be written to this app's protected storage.
 * Inspect/read performs fixed-local-domain pair-consistency crypto, never an ACS nonce proof.
 */
package org.rcsrs.standalonecheckin;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.nio.*;
import java.nio.charset.*;

public final class MlsIdentity {
    public static final int RECORD_MAX=8192,NONCE_MAX=16384;
    public static final class ProofStats {
        public final int nonceBytes,signatureBytes;public final boolean verified;
        private ProofStats(int n,int s,boolean v){nonceBytes=n;signatureBytes=s;verified=v;}
    }
    private static final int MAGIC=0x524d4c31,VERSION=1;
    private static final byte[] CONSISTENCY_DOMAIN="rcsrs-own-mls-key-consistency-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL="MLS 1.0 ACS_Participant_Key_Proof".getBytes(StandardCharsets.US_ASCII);
    private final KeyPair participant,device;private final byte[] binding;private final boolean reloaded;
    private MlsIdentity(KeyPair participant,KeyPair device,byte[] binding,boolean reloaded){
        this.participant=participant;this.device=device;this.binding=binding.clone();this.reloaded=reloaded;
    }
    public static void validateTag(String tag)throws IOException{tagBytes(tag);}
    private static byte[] tagBytes(String tag)throws IOException{
        if(tag==null || !tag.matches("[0-9a-f]{64}"))throw new IOException();
        byte[] bytes=new byte[32];for(int i=0;i<bytes.length;i++)bytes[i]=(byte)Integer.parseInt(tag.substring(i*2,i*2+2),16);return bytes;
    }
    public static MlsIdentity create(String tag)throws IOException{
        byte[] binding=tagBytes(tag);
        try{
            KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair p=generator.generateKeyPair(),d=generator.generateKeyPair();validatePair(p);validatePair(d);
            if(Arrays.equals(p.getPublic().getEncoded(),d.getPublic().getEncoded()))throw new IOException();
            return new MlsIdentity(p,d,binding,false);
        }catch(GeneralSecurityException invalid){throw new IOException();}
    }
    private static void validatePair(KeyPair pair)throws GeneralSecurityException,IOException{
        if(!(pair.getPublic() instanceof ECPublicKey) || !(pair.getPrivate() instanceof ECPrivateKey))throw new IOException();
        AlgorithmParameters parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected=parameters.getParameterSpec(ECParameterSpec.class);
        for(ECKey key:Arrays.asList((ECPublicKey)pair.getPublic(),(ECPrivateKey)pair.getPrivate())){
            ECParameterSpec actual=key.getParams();
            if(actual==null || !expected.getCurve().equals(actual.getCurve()) || !expected.getGenerator().equals(actual.getGenerator()) ||
                !expected.getOrder().equals(actual.getOrder()) || expected.getCofactor()!=actual.getCofactor())throw new IOException();
        }
        ECPrivateKey secret=(ECPrivateKey)pair.getPrivate();
        if(secret.getS().signum()<=0 || secret.getS().compareTo(expected.getOrder())>=0)throw new IOException();
        // Standard JCA pair check only: local fixed domain, not an ACS nonce proof.
        byte[] consistency=null;
        try{
            Signature signer=Signature.getInstance("SHA256withECDSA");signer.initSign(pair.getPrivate());signer.update(CONSISTENCY_DOMAIN);
            consistency=signer.sign();
            Signature verifier=Signature.getInstance("SHA256withECDSA");verifier.initVerify(pair.getPublic());verifier.update(CONSISTENCY_DOMAIN);
            if(consistency.length==0 || consistency.length>128 || !verifier.verify(consistency))throw new IOException();
        }finally{if(consistency!=null)Arrays.fill(consistency,(byte)0);}
        // No custom EC derivation, point math, public/private export or network.
    }
    private static byte[] hash(byte[] value)throws IOException{
        try{return MessageDigest.getInstance("SHA-256").digest(value);}catch(GeneralSecurityException invalid){throw new IOException();}
    }
    private static byte[] pairBaseline(byte[] pub,byte[] priv)throws IOException{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeInt(pub.length);out.write(pub);out.writeInt(priv.length);out.write(priv);out.flush();byte[] encoded=bytes.toByteArray();
        try{return hash(encoded);}finally{Arrays.fill(encoded,(byte)0);}
    }
    private static void field(DataOutputStream out,byte[] data,int max)throws IOException{
        if(data==null || data.length==0 || data.length>max)throw new IOException();out.writeInt(data.length);out.write(data);
    }
    private static byte[] field(DataInputStream in,int max)throws IOException{
        int length=in.readInt();if(length<=0 || length>max || length>in.available())throw new IOException();
        byte[] value=new byte[length];in.readFully(value);return value;
    }
    /** PRIVATE persistence API: never supply an external file, log, socket or host stream. */
    public void writePrivate(OutputStream destination)throws IOException{
        byte[] p=participant.getPublic().getEncoded(),ps=participant.getPrivate().getEncoded();
        byte[] d=device.getPublic().getEncoded(),ds=device.getPrivate().getEncoded(),body=null;
        try{
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeInt(MAGIC);out.writeInt(VERSION);out.write(binding);
            out.write(pairBaseline(p,ps));out.write(pairBaseline(d,ds));
            field(out,p,1024);field(out,ps,2048);field(out,d,1024);field(out,ds,2048);out.flush();body=bytes.toByteArray();
            if(body.length+32>RECORD_MAX)throw new IOException();destination.write(body);destination.write(hash(body));destination.flush();
        }finally{if(ps!=null)Arrays.fill(ps,(byte)0);if(ds!=null)Arrays.fill(ds,(byte)0);if(body!=null)Arrays.fill(body,(byte)0);}
    }
    public static MlsIdentity readPrivate(InputStream input,String tag)throws IOException{
        byte[] expected=tagBytes(tag),record=null,body=null,ps=null,ds=null;
        try{
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();byte[] block=new byte[1024];int count;
            while((count=input.read(block))!=-1){if(count<=0 || count>RECORD_MAX-bytes.size())throw new IOException();bytes.write(block,0,count);}
            record=bytes.toByteArray();if(record.length<8+32+64+16+32)throw new IOException();
            body=Arrays.copyOf(record,record.length-32);
            if(!MessageDigest.isEqual(hash(body),Arrays.copyOfRange(record,body.length,record.length)))throw new IOException();
            DataInputStream in=new DataInputStream(new ByteArrayInputStream(body));
            if(in.readInt()!=MAGIC || in.readInt()!=VERSION)throw new IOException();
            byte[] stored=new byte[32];in.readFully(stored);if(!MessageDigest.isEqual(expected,stored))throw new IOException();
            byte[] ph=new byte[32],dh=new byte[32];in.readFully(ph);in.readFully(dh);
            byte[] p=field(in,1024);ps=field(in,2048);byte[] d=field(in,1024);ds=field(in,2048);
            if(in.available()!=0 || !MessageDigest.isEqual(ph,pairBaseline(p,ps)) || !MessageDigest.isEqual(dh,pairBaseline(d,ds)))throw new IOException();
            KeyFactory factory=KeyFactory.getInstance("EC");
            KeyPair participant=new KeyPair(factory.generatePublic(new X509EncodedKeySpec(p)),factory.generatePrivate(new PKCS8EncodedKeySpec(ps)));
            KeyPair device=new KeyPair(factory.generatePublic(new X509EncodedKeySpec(d)),factory.generatePrivate(new PKCS8EncodedKeySpec(ds)));
            validatePair(participant);validatePair(device);
            if(Arrays.equals(p,d))throw new IOException();
            return new MlsIdentity(participant,device,stored,true);
        }catch(GeneralSecurityException | IllegalArgumentException invalid){throw new IOException();}
        finally{for(byte[] secret:new byte[][]{record,body,ps,ds})if(secret!=null)Arrays.fill(secret,(byte)0);}
    }
    public boolean participantContinuity(){return reloaded;}
    public boolean deviceContinuity(){return reloaded;}
    /**
     * In-process/JNI public proof only: [cloned participant SPKI DER, cloned DER ECDSA].
     * Caller owns both arrays; never export them to diagnostics, host files or logs.
     * Requires an already-reloaded validated identity; never creates/loads/updates one.
     */
    public byte[][] signParticipantProof(byte[] exactNonceUtf8)throws IOException{
        return signVerifiedParticipant(exactNonceUtf8,()->{});
    }
    public ProofStats signAndVerify(byte[] nonce)throws IOException{return signAndVerify(nonce,()->{});}
    public ProofStats signAndVerify(byte[] nonce,Runnable verificationStage)throws IOException{
        byte[][] proof=signVerifiedParticipant(nonce,verificationStage);
        try{return new ProofStats(nonce.length,proof[1].length,true);}
        finally{for(byte[] value:proof)Arrays.fill(value,(byte)0);}
    }
    private byte[][] signVerifiedParticipant(byte[] nonce,Runnable verificationStage)throws IOException{
        if(!reloaded || verificationStage==null || nonce==null || nonce.length==0 || nonce.length>NONCE_MAX)throw new IOException();
        byte[] exact=nonce.clone(),content=null,signature=null,spki=null;
        try{
            content=signingInput(exact);
            Signature signer=Signature.getInstance("SHA256withECDSA");signer.initSign(participant.getPrivate());signer.update(content);signature=signer.sign();
            verificationStage.run();
            Signature verifier=Signature.getInstance("SHA256withECDSA");verifier.initVerify(participant.getPublic());verifier.update(content);
            if(signature.length==0 || signature.length>128 || !verifier.verify(signature))throw new IOException();
            spki=participant.getPublic().getEncoded();if(spki==null || spki.length==0 || spki.length>1024)throw new IOException();
            return new byte[][]{spki.clone(),signature.clone()};
        }catch(GeneralSecurityException invalid){throw new IOException();}
        finally{for(byte[] value:new byte[][]{exact,content,signature,spki})if(value!=null)Arrays.fill(value,(byte)0);}
    }
    public static byte[] decodeNonce(String encoded)throws IOException{
        if(encoded==null || encoded.isEmpty() || encoded.length()>4*((NONCE_MAX+2)/3) || !encoded.matches("[A-Za-z0-9+/]+={0,2}"))throw new IOException();
        try{
            byte[] bytes=Base64.getDecoder().decode(encoded);
            if(!Base64.getEncoder().encodeToString(bytes).equals(encoded))throw new IOException();validateNonce(bytes);return bytes;
        }catch(IllegalArgumentException invalid){throw new IOException();}
    }
    private static void validateNonce(byte[] nonce)throws IOException{
        if(nonce==null || nonce.length==0 || nonce.length>NONCE_MAX)throw new IOException();
        try{
            String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(nonce)).toString();
            for(int i=0;i<text.length();i++)if(Character.isISOControl(text.charAt(i)))throw new IOException();
        }catch(CharacterCodingException invalid){throw new IOException();}
    }
    private static void vl(DataOutputStream out,int n)throws IOException{
        if(n<64)out.writeByte(n);else if(n<16384)out.writeShort(n|0x4000);else out.writeInt(n|0x80000000);
    }
    private static byte[] signingInput(byte[] nonce)throws IOException{
        validateNonce(nonce);ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        vl(out,LABEL.length);out.write(LABEL);vl(out,nonce.length);out.write(nonce);out.flush();return bytes.toByteArray();
    }
    private interface Trial{void run()throws Exception;}
    private static int rejected;
    private static void bad(Trial t)throws Exception{try{t.run();}catch(IOException expected){rejected++;return;}throw new AssertionError();}
    private static void check(boolean b){if(!b)throw new AssertionError();}
    private static byte[] unhex(String text){byte[] b=new byte[text.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(text.substring(2*i,2*i+2),16);return b;}
    private static byte[] reseal(byte[] record)throws IOException{
        byte[] value=record.clone(),body=Arrays.copyOf(value,value.length-32);
        System.arraycopy(hash(body),0,value,value.length-32,32);return value;
    }
    public static void main(String[] ignored)throws Exception{
        String tag=String.join("",Collections.nCopies(64,"a"));
        // Independent literal RFC9420 vector; Rust short/64-byte fixtures use this label.
        byte[] shortVector=unhex("214d4c5320312e30204143535f5061727469636970616e745f4b65795f50726f6f66056e6f6e6365");
        check(Arrays.equals(signingInput("nonce".getBytes("UTF-8")),shortVector));
        byte[] n64=new byte[64];Arrays.fill(n64,(byte)'n');byte[] x=signingInput(n64);
        check(x[34]==0x40 && x[35]==0x40 && x.length==100);
        byte[] nMax=new byte[NONCE_MAX];Arrays.fill(nMax,(byte)'n');x=signingInput(nMax);
        check(x[34]==(byte)0x80 && x[35]==0 && x[36]==0x40 && x[37]==0 && x.length==NONCE_MAX+38);
        MlsIdentity first=create(tag);bad(()->first.signAndVerify("nonce".getBytes("UTF-8")));ByteArrayOutputStream storage=new ByteArrayOutputStream();first.writePrivate(storage);byte[] record=storage.toByteArray();
        MlsIdentity second=readPrivate(new ByteArrayInputStream(record),tag);
        check(second.participantContinuity()&&second.deviceContinuity());
        byte[] proofNonce="new-own-callback-nonce".getBytes("UTF-8");
        byte[][] actualProof=second.signParticipantProof(proofNonce);check(actualProof.length==2);
        KeyFactory proofFactory=KeyFactory.getInstance("EC");
        PublicKey proofPublic=proofFactory.generatePublic(new X509EncodedKeySpec(actualProof[0]));
        Signature proofVerifier=Signature.getInstance("SHA256withECDSA");proofVerifier.initVerify(proofPublic);
        proofVerifier.update(signingInput(proofNonce));check(proofVerifier.verify(actualProof[1]));
        proofVerifier.initVerify(proofPublic);proofVerifier.update(signingInput("wrong-own-callback-nonce".getBytes("UTF-8")));check(!proofVerifier.verify(actualProof[1]));
        byte[] changedSignature=actualProof[1].clone();changedSignature[changedSignature.length-1]^=1;
        proofVerifier.initVerify(proofPublic);proofVerifier.update(signingInput(proofNonce));check(!proofVerifier.verify(changedSignature));
        byte[] originalPublic=actualProof[0].clone();Arrays.fill(actualProof[0],(byte)0);Arrays.fill(actualProof[1],(byte)0);
        byte[][] againProof=second.signParticipantProof("next-own-callback-nonce".getBytes("UTF-8"));check(Arrays.equals(originalPublic,againProof[0]));
        proofVerifier.initVerify(proofFactory.generatePublic(new X509EncodedKeySpec(againProof[0])));
        proofVerifier.update(signingInput("next-own-callback-nonce".getBytes("UTF-8")));check(proofVerifier.verify(againProof[1]));
        bad(()->first.signParticipantProof(proofNonce));
        bad(()->second.signParticipantProof(new byte[0]));bad(()->second.signParticipantProof(new byte[NONCE_MAX+1]));
        bad(()->second.signParticipantProof(null));bad(()->second.signParticipantProof(new byte[]{(byte)255}));bad(()->second.signParticipantProof(new byte[]{10}));
        int[] stageCalls={0};ProofStats staged=second.signAndVerify(proofNonce,()->stageCalls[0]++);
        check(staged.verified&&stageCalls[0]==1&&staged.nonceBytes==proofNonce.length);
        bad(()->second.signAndVerify(new byte[]{(byte)255},()->stageCalls[0]++));check(stageCalls[0]==1);
        ProofStats proof=second.signAndVerify("nonce".getBytes("UTF-8"));check(proof.verified&&proof.nonceBytes==5&&proof.signatureBytes>0);
        check(second.signAndVerify(n64).verified);check(second.signAndVerify(nMax).verified);
        ByteArrayOutputStream again=new ByteArrayOutputStream();second.writePrivate(again);check(Arrays.equals(record,again.toByteArray()));
        for(int i=0;i<record.length;i++){final int n=i;bad(()->readPrivate(new ByteArrayInputStream(Arrays.copyOf(record,n)),tag));}
        for(int i=0;i<record.length;i++){byte[] changed=record.clone();changed[i]^=1;bad(()->readPrivate(new ByteArrayInputStream(changed),tag));}
        // Recomputed outer checksum forces validation of structure and both role baselines.
        for(int offset:new int[]{0,4,8,40,72,104,108}){
            byte[] changed=record.clone();changed[offset]^=1;byte[] sealed=reseal(changed);
            bad(()->readPrivate(new ByteArrayInputStream(sealed),tag));
        }
        int publicLength=java.nio.ByteBuffer.wrap(record,104,4).getInt();
        int privateStart=108+publicLength+4;byte[] changedPrivate=record.clone();changedPrivate[privateStart]^=1;
        bad(()->readPrivate(new ByteArrayInputStream(reseal(changedPrivate)),tag));
        byte[] surplus=Arrays.copyOf(record,record.length+1);surplus=reseal(surplus);final byte[] trailing=surplus;
        bad(()->readPrivate(new ByteArrayInputStream(trailing),tag));
        KeyPairGenerator otherCurve=KeyPairGenerator.getInstance("EC");otherCurve.initialize(new ECGenParameterSpec("secp384r1"));
        MlsIdentity wrongCurve=new MlsIdentity(otherCurve.generateKeyPair(),otherCurve.generateKeyPair(),tagBytes(tag),false);
        ByteArrayOutputStream invalidStore=new ByteArrayOutputStream();wrongCurve.writePrivate(invalidStore);
        bad(()->readPrivate(new ByteArrayInputStream(invalidStore.toByteArray()),tag));
        // Same-curve mismatches have valid baselines/checksum but must fail pair consistency.
        MlsIdentity mismatchedParticipant=new MlsIdentity(new KeyPair(first.participant.getPublic(),first.device.getPrivate()),first.device,tagBytes(tag),false);
        ByteArrayOutputStream mismatchP=new ByteArrayOutputStream();mismatchedParticipant.writePrivate(mismatchP);
        bad(()->readPrivate(new ByteArrayInputStream(mismatchP.toByteArray()),tag));
        MlsIdentity mismatchedDevice=new MlsIdentity(first.participant,new KeyPair(first.device.getPublic(),first.participant.getPrivate()),tagBytes(tag),false);
        ByteArrayOutputStream mismatchD=new ByteArrayOutputStream();mismatchedDevice.writePrivate(mismatchD);
        bad(()->readPrivate(new ByteArrayInputStream(mismatchD.toByteArray()),tag));
        // Independent literal-content JCA verifier, plus changed-content/raw-nonce rejection.
        Signature signer=Signature.getInstance("SHA256withECDSA");signer.initSign(second.participant.getPrivate());signer.update(shortVector);byte[] syntheticSignature=signer.sign();
        Signature verifier=Signature.getInstance("SHA256withECDSA");verifier.initVerify(second.participant.getPublic());verifier.update(signingInput("nonce".getBytes("UTF-8")));check(verifier.verify(syntheticSignature));
        verifier.initVerify(second.participant.getPublic());verifier.update("nonce".getBytes("UTF-8"));check(!verifier.verify(syntheticSignature));
        byte[] altered=shortVector.clone();altered[altered.length-1]^=1;verifier.initVerify(second.participant.getPublic());verifier.update(altered);check(!verifier.verify(syntheticSignature));
        bad(()->readPrivate(new ByteArrayInputStream(Arrays.copyOf(record,record.length+1)),tag));
        bad(()->readPrivate(new ByteArrayInputStream(new byte[RECORD_MAX+1]),tag));
        bad(()->readPrivate(new ByteArrayInputStream(record),String.join("",Collections.nCopies(64,"b"))));
        bad(()->create("short"));bad(()->create(tag.toUpperCase(Locale.ROOT)));
        check(Arrays.equals(decodeNonce("bm9uY2U="),"nonce".getBytes("UTF-8")));check(Arrays.equals(decodeNonce("zrs="),"λ".getBytes("UTF-8")));
        for(String input:Arrays.asList("bm9uY2U","bm9uY2U=\n","","/w==","Cg==","AA==","wqA=\n"))bad(()->decodeNonce(input));
        bad(()->signingInput(new byte[0]));bad(()->signingInput(new byte[NONCE_MAX+1]));
        // All key/record fixtures in this main are synthetic; never load app state here.
        Arrays.fill(record,(byte)0);
        System.out.println("mls_identity_selfcheck_passed rejections="+rejected);
    }
}
