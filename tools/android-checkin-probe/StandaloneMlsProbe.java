/* Copyright (C) 2026 rcs-rs contributors. SPDX-License-Identifier: Apache-2.0
 * Ordinary own-app local identity/proof diagnostic; no Google SDK/native-MLS,
 * enrollment, HTTP, phone, caller privilege, existing private key or role use.
 */
package org.rcsrs.standalonecheckin;

import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.*;
import android.system.Os;
import android.system.OsConstants;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.*;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.Arrays;

/** Normal own-UID storage; never returns keys, hashes, signatures, tags or nonce values.
 * Inspect validates stored pairs with discarded fixed-local-domain JCA signatures;
 * it creates no identity and produces no ACS nonce proof. signature_verified refers
 * only to the caller-supplied ACS nonce proof in explicit sign mode.
 */
public final class StandaloneMlsProbe extends Instrumentation {
    private static final String PACKAGE="org.rcsrs.standalonecheckin";
    private String mode="inspect",stage="context",status="failed",tag,encodedNonce;
    private boolean nonceArgument;
    private boolean ownContext,ordinary,checkinPresent,present,created,reloaded,pContinuity,dContinuity,verified;
    private int nonceBytes,signatureBytes;
    @Override public void onCreate(Bundle args){
        super.onCreate(args);
        if(args!=null){
            if(args.containsKey("mode"))mode=args.getString("mode");
            tag=args.getString("binding_tag");nonceArgument=args.containsKey("nonce_base64");encodedNonce=args.getString("nonce_base64");
        }
        start();
    }
    @Override public void onStart(){
        byte[] nonce=null;
        try{
            Context context=getTargetContext().getApplicationContext();ApplicationInfo info=context.getApplicationInfo();
            ownContext=PACKAGE.equals(context.getPackageName()) && PACKAGE.equals(getContext().getPackageName());
            ordinary=info.uid>=10000 && info.uid<20000 && info.uid==android.os.Process.myUid() &&
                (info.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))==0;
            if(!ownContext || !ordinary || Looper.myLooper()==Looper.getMainLooper() ||
                !("inspect".equals(mode)||"sign".equals(mode)))throw new IOException();
            stage="identity";checkOwnRegistration(context);checkinPresent=true;
            stage="input";MlsIdentity.validateTag(tag);
            if("inspect".equals(mode)){if(nonceArgument)throw new IOException();}
            else{nonce=MlsIdentity.decodeNonce(encodedNonce);nonceBytes=nonce.length;}
            encodedNonce=null;
            stage="storage";File record=new File(context.getFilesDir(),"own-mls-v1-"+tag+".bin");
            if("inspect".equals(mode)){
                MlsIdentity identity=readExisting(record);
                status=identity==null?"no_identity":"ready";stage="complete";
            }else{
                File lockFile=new File(context.getFilesDir(),"own-mls-v1-"+tag+".lock");
                if(exists(lockFile) && !Files.isRegularFile(lockFile.toPath(),LinkOption.NOFOLLOW_LINKS))throw new IOException();
                try(RandomAccessFile lock=new RandomAccessFile(lockFile,"rw");FileLock lease=lock.getChannel().tryLock()){
                    if(lease==null)throw new IOException();
                    MlsIdentity identity=readExisting(record);
                    if(identity==null){
                        stage="create";identity=MlsIdentity.create(tag);created=true;
                        stage="persist";persistNew(record,identity);
                        stage="reload";identity=readExisting(record);if(identity==null)throw new IOException();
                    }
                    stage="sign";MlsIdentity.ProofStats stats=identity.signAndVerify(nonce,()->stage="verify");
                    stage="verify";if(!stats.verified || stats.nonceBytes!=nonce.length || stats.signatureBytes<=0)throw new IOException();
                    verified=true;signatureBytes=stats.signatureBytes;status="signed";stage="complete";
                }
            }
        }catch(Exception | LinkageError safeFailure){status="failed";}
        finally{if(nonce!=null)Arrays.fill(nonce,(byte)0);encodedNonce=null;tag=null;}
        emit();
    }
    private static void checkOwnRegistration(Context context)throws IOException{
        File f=new File(context.getFilesDir(),"own-checkin-v1.bin");
        if(!Files.isRegularFile(f.toPath(),LinkOption.NOFOLLOW_LINKS) || exists(new File(f.getPath()+".bak")) ||
            exists(new File(f.getPath()+".new")) || f.length()!=24)throw new IOException();
        try(DataInputStream in=new DataInputStream(new FileInputStream(f))){
            if(in.readInt()!=0x52435331 || in.readInt()!=1 || in.readLong()==0 || in.readLong()==0 || in.read()!=-1)throw new IOException();
        }
    }
    private static boolean exists(File f){return Files.exists(f.toPath(),LinkOption.NOFOLLOW_LINKS);}
    private static void guardSidecars(File f)throws IOException{
        if(exists(new File(f.getPath()+".bak")) || exists(new File(f.getPath()+".new")))throw new IOException();
    }
    private MlsIdentity readExisting(File file)throws IOException{
        guardSidecars(file);if(!exists(file))return null;
        if(!Files.isRegularFile(file.toPath(),LinkOption.NOFOLLOW_LINKS) || file.length()>MlsIdentity.RECORD_MAX)throw new IOException();
        MlsIdentity identity;
        try(InputStream in=new FileInputStream(file)){identity=MlsIdentity.readPrivate(in,tag);}
        present=true;reloaded=true;pContinuity=identity.participantContinuity();dContinuity=identity.deviceContinuity();
        if(!pContinuity || !dContinuity)throw new IOException();return identity;
    }
    private static void persistNew(File file,MlsIdentity identity)throws Exception{
        // Every supported writer holds this tag's lock. No existing/partial state is replaced.
        guardSidecars(file);if(exists(file))throw new IOException();AtomicFile atomic=new AtomicFile(file);FileOutputStream stream=null;
        try{
            stream=atomic.startWrite();Os.fchmod(stream.getFD(),0600);
            identity.writePrivate(stream);stream.flush();stream.getFD().sync();atomic.finishWrite(stream);stream=null;
            FileDescriptor directory=Os.open(file.getParent(),OsConstants.O_RDONLY,0);
            try{Os.fsync(directory);}finally{Os.close(directory);}
            guardSidecars(file);if(!exists(file))throw new IOException();
        }finally{if(stream!=null)atomic.failWrite(stream);}
    }
    private void emit(){
        Bundle out=new Bundle();try{
            JSONObject r=new JSONObject();r.put("schema_version",1);r.put("mode","sign".equals(mode)?"sign":"inspect");
            r.put("stage",stage);r.put("status",status);r.put("own_context",ownContext);r.put("ordinary_uid",ordinary);
            r.put("own_checkin_present",checkinPresent);r.put("identity_present",present);r.put("identity_created",created);
            r.put("identity_reloaded",reloaded);r.put("participant_continuity",pContinuity);r.put("device_continuity",dContinuity);
            r.put("signature_verified",verified);r.put("attestation_verified",false);r.put("enrolled",false);
            r.put("nonce_bytes",nonceBytes);r.put("signature_bytes",signatureBytes);out.putString("standalone_mls",r.toString());
        }catch(Exception ignored){finish(1,out);return;}
        finish("failed".equals(status)?1:0,out);
    }
}
