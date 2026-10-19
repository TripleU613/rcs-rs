/* Copyright (C) 2026 rcs-rs contributors. SPDX-License-Identifier: Apache-2.0 */
package org.rcsrs.standalonecheckin;

import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.*;
import android.system.Os;
import android.system.OsConstants;
import android.util.AtomicFile;
import org.json.JSONObject;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.nio.channels.FileLock;
import java.util.*;

/** Private diagnostic host: no dependencies on GMS, phone APIs or another app's data. */
public final class StandaloneCheckinProbe extends Instrumentation {
    private static final String PACKAGE="org.rcsrs.standalonecheckin";
    private static final int MAGIC=0x52435331;
    private String mode="inspect",stage="context",status="failed";
    private boolean ownContext,ordinary,attempt,credentials,network;
    private int http,bytes;
    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        if(args!=null && args.containsKey("mode")) mode=args.getString("mode");
        start();
    }
    @Override public void onStart() {
        try {
            Context context=getTargetContext().getApplicationContext();
            ApplicationInfo info=context.getApplicationInfo();
            ownContext=PACKAGE.equals(context.getPackageName()) && PACKAGE.equals(getContext().getPackageName());
            ordinary=info.uid>=10000 && info.uid==android.os.Process.myUid() &&
                (info.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))==0;
            if(!ownContext || !ordinary || Looper.myLooper()==Looper.getMainLooper() ||
                    !("inspect".equals(mode)||"register".equals(mode))) throw new IOException();
            stage="storage";
            File state=new File(context.getFilesDir(),"own-checkin-v1.bin");
            if("inspect".equals(mode)) { load(state); existing(); }
            else {
                try(RandomAccessFile lock=new RandomAccessFile(new File(context.getFilesDir(),"own-checkin.lock"),"rw");
                    FileLock lease=lock.getChannel().tryLock()) {
                    if(lease==null) throw new IOException();
                    load(state);
                    if(attempt || credentials) existing(); else register(state);
                }
            }
        } catch(Exception safeFailure) { status="failed"; }
        emit();
    }
    private void existing() { status=credentials?"credentials_present":attempt?"attempt_already_recorded":"ready"; stage="complete"; }
    private CheckinWire.Credentials load(File file) throws IOException {
        if(new File(file.getPath()+".bak").exists() || new File(file.getPath()+".new").exists()) throw new IOException();
        if(!file.exists()) { attempt=false; credentials=false; return new CheckinWire.Credentials(0,0); }
        if(file.length()!=24) throw new IOException();
        try(DataInputStream in=new DataInputStream(new FileInputStream(file))) {
            if(in.readInt()!=MAGIC || in.readInt()!=1) throw new IOException();
            long id=in.readLong(), token=in.readLong();
            if((id==0)!=(token==0) || in.read()!=-1) throw new IOException();
            attempt=true; credentials=id!=0 && token!=0;
            return new CheckinWire.Credentials(id,token);
        }
    }
    private void persist(File file,long id,long token) throws Exception {
        AtomicFile atomic=new AtomicFile(file); FileOutputStream stream=null;
        try {
            stream=atomic.startWrite(); DataOutputStream data=new DataOutputStream(stream);
            data.writeInt(MAGIC); data.writeInt(1); data.writeLong(id); data.writeLong(token);
            data.flush(); stream.getFD().sync(); atomic.finishWrite(stream); stream=null;
            FileDescriptor directory=Os.open(file.getParent(),OsConstants.O_RDONLY,0);
            try { Os.fsync(directory); } finally { Os.close(directory); }
            CheckinWire.Credentials stored=load(file);
            if(!attempt || stored.id!=id || stored.token!=token) throw new IOException();
        } finally { if(stream!=null) atomic.failWrite(stream); }
    }
    private void register(File file) throws Exception {
        stage="request";
        Map<Integer,String> build=new HashMap<>();
        put(build,1,Build.FINGERPRINT); put(build,2,Build.HARDWARE); put(build,3,Build.BRAND);
        put(build,5,Build.BOOTLOADER); put(build,9,Build.DEVICE); put(build,11,Build.MODEL);
        put(build,12,Build.MANUFACTURER); put(build,13,Build.PRODUCT);
        byte[] request=CheckinWire.gzip(CheckinWire.request(build,Build.VERSION.SDK_INT,Build.TIME<0?-1:Build.TIME/1000));
        if(request.length>CheckinWire.COMPRESSED_MAX) throw new IOException();
        stage="attempt_marker"; persist(file,0,0);
        stage="http";
        final long deadline=SystemClock.elapsedRealtime()+45000;
        HttpsURLConnection connection=(HttpsURLConnection)new URL("https://android.clients.google.com/checkin").openConnection();
        try {
            connection.setRequestMethod("POST"); connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(15000); connection.setReadTimeout(15000);
            connection.setDoOutput(true); connection.setUseCaches(false);
            connection.setFixedLengthStreamingMode(request.length);
            connection.setRequestProperty("Content-Type","application/x-protobuffer");
            connection.setRequestProperty("Content-Encoding","gzip");
            connection.setRequestProperty("Accept-Encoding","gzip");
            connection.setRequestProperty("User-Agent","rcsrs-standalonecheckin/0.1.0");
            network=true;
            try(OutputStream out=connection.getOutputStream()){ out.write(request); }
            int code=connection.getResponseCode();
            if(code<100 || code>599) throw new IOException(); http=code;
            if(http!=200) { status="http_rejected"; return; }
            stage="response";
            if(connection.getContentLengthLong()>CheckinWire.COMPRESSED_MAX) throw new IOException();
            String encoding=connection.getContentEncoding();
            boolean gzip="gzip".equalsIgnoreCase(encoding);
            if(encoding!=null && !encoding.isEmpty() && !gzip && !"identity".equalsIgnoreCase(encoding)) throw new IOException();
            byte[] response;
            try(InputStream raw=connection.getInputStream(); InputStream bounded=new FilterInputStream(raw) {
                private void check() throws IOException { if(SystemClock.elapsedRealtime()>deadline) throw new IOException(); }
                @Override public int read(byte[] b,int off,int len) throws IOException {
                    check(); int n=super.read(b,off,len); check(); return n;
                }
                @Override public int read() throws IOException { check(); int n=super.read(); check(); return n; }
            }) { response=CheckinWire.response(bounded,gzip); }
            bytes=response.length;
            CheckinWire.Credentials issued=CheckinWire.parse(response);
            if(SystemClock.elapsedRealtime()>deadline) throw new IOException();
            stage="persist"; persist(file,issued.id,issued.token);
            status="registered"; stage="complete";
        } finally { connection.disconnect(); }
    }
    private static void put(Map<Integer,String> map,int field,String value) {
        if(value!=null && !value.isEmpty() && !Build.UNKNOWN.equals(value)) map.put(field,value);
    }
    private void emit() {
        Bundle output=new Bundle();
        try {
            JSONObject result=new JSONObject(); result.put("schema_version",1);
            result.put("mode","register".equals(mode)?"register":"inspect");
            result.put("stage",stage); result.put("status",status);
            result.put("own_context",ownContext); result.put("ordinary_uid",ordinary);
            result.put("attempt_recorded",attempt); result.put("credentials_present",credentials);
            result.put("network_attempted",network); result.put("http_code",http); result.put("response_bytes",bytes);
            output.putString("standalone_checkin",result.toString());
        } catch(Exception ignored) { finish(1,output); return; }
        finish(("failed".equals(status)||"http_rejected".equals(status))?1:0,output);
    }
}
