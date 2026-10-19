/* Copyright (C) 2026 rcs-rs contributors. SPDX-License-Identifier: Apache-2.0
 * Private same-process validation/lifecycle boundary. No context, files or network.
 */
package org.rcsrs.standalonecheckin;
import java.io.IOException;
import java.util.*;
public final class DirectVmBoundary {
    public static final int DIRECT_MAX=64*1024;
    private static final Set<String> REQUIRED=new HashSet<>(Arrays.asList("APP_NAME","PROVISIONING_SESSION_ID","DROIDGUARD_SALT",
        "DROIDGUARD_CONTENT_BINDING_VERSION","JIBE_ACS_COOKIE","SIM_AUTH_TEMP_TOKEN","DROIDGUARD_CHALLENGE"));
    public static Map<String,String> directInputs(String[] keys,String[] values)throws IOException{
        if(keys==null || values==null || keys.length!=values.length || keys.length<7 || keys.length>9)throw new IOException();
        Map<String,String> inputs=new LinkedHashMap<>();
        for(int i=0;i<keys.length;i++){
            String key=keys[i],value=values[i];
            if(key==null || (!REQUIRED.contains(key) && !key.equals("IMSI") && !key.equals("IMEI")) ||
                value==null || !value.matches("[0-9a-f]{96}") || inputs.put(key,value)!=null)throw new IOException();
        }
        if(!inputs.keySet().containsAll(REQUIRED))throw new IOException();return Collections.unmodifiableMap(inputs);
    }
    public interface Operation {
        void construct()throws Exception;void supported()throws Exception;boolean init()throws Exception;
        byte[] snapshot()throws Exception;void close()throws Exception;void verifyArtifacts()throws Exception;
    }
    /** close must be a no-op unless construction returned an owned handle. */
    public static byte[] execute(Operation op,int max)throws Exception{
        if(op==null || max<=0 || max>1024*1024)throw new IOException();byte[] raw=null;boolean complete=false;
        try{
            try{
                op.construct();op.supported();if(!op.init())throw new IOException();op.supported();
                raw=op.snapshot();op.supported();validate(raw,max);
            }finally{
                try{op.close();}finally{try{op.verifyArtifacts();}finally{op.supported();}}
            }
            validate(raw,max);complete=true;return raw;
        }finally{if(!complete && raw!=null)Arrays.fill(raw,(byte)0);}
    }
    private static void validate(byte[] raw,int max)throws IOException{
        if(raw==null || raw.length==0 || raw.length>max)throw new IOException();byte[] prefix={'E','R','R','O','R',' ',':',' '};
        if(raw.length>=prefix.length){boolean match=true;for(int i=0;i<prefix.length;i++)if(raw[i]!=prefix[i])match=false;if(match)throw new IOException();}
    }
    private interface Trial{void run()throws Exception;}
    private static int rejected;
    private static void bad(Trial test)throws Exception{try{test.run();}catch(IOException expected){rejected++;return;}throw new AssertionError();}
    private static void check(boolean b){if(!b)throw new AssertionError();}
    private static final class Fake implements Operation {
        final List<String> steps=new ArrayList<>();final byte[] result;final String fail;int checkCount;boolean made;
        Fake(String fail){this(fail,new byte[]{1,2,3});}
        Fake(String fail,byte[] result){this.fail=fail;this.result=result;}
        private void step(String s)throws IOException{steps.add(s);if(s.equals(fail))throw new IOException();}
        public void construct()throws Exception{step("construct");made=true;}
        public void supported()throws Exception{step("supported"+(++checkCount));}
        public boolean init()throws Exception{step("init");return !fail.equals("init_false");}
        public byte[] snapshot()throws Exception{step("snapshot");return result;}
        public void close()throws Exception{
            if(fail.equals("close_linkage")){steps.add("close");throw new UnsatisfiedLinkError();}
            step(made?"close":"no_handle");
            if(fail.equals("close_error_bytes"))System.arraycopy(new byte[]{'E','R','R','O','R',' ',':',' '},0,result,0,8);
        }
        public void verifyArtifacts()throws Exception{step("artifacts");}
    }
    public static void main(String[] ignored)throws Exception{
        String[] keys=REQUIRED.toArray(new String[0]),values=new String[keys.length];Arrays.fill(values,String.join("",Collections.nCopies(96,"a")));
        Map<String,String> parsed=directInputs(keys,values);check(parsed.size()==7 && parsed.get("APP_NAME").equals(values[0]));
        String saved=parsed.get(keys[0]);values[0]="bad";check(parsed.get(keys[0]).equals(saved));values[0]=saved;
        for(String replacement:new String[]{null,"_seigd","UNKNOWN",keys[1]}){String[] changed=keys.clone();changed[0]=replacement;bad(()->directInputs(changed,values));}
        for(String replacement:new String[]{null,"","A"+saved.substring(1),saved.substring(1),saved+"0","\n"+saved.substring(1)}){String[] changed=values.clone();changed[0]=replacement;bad(()->directInputs(keys,changed));}
        bad(()->directInputs(null,values));bad(()->directInputs(keys,null));bad(()->directInputs(Arrays.copyOf(keys,6),Arrays.copyOf(values,6)));
        String[] missing=keys.clone();missing[0]="IMSI";bad(()->directInputs(missing,values));
        bad(()->directInputs(Arrays.copyOf(keys,10),Arrays.copyOf(values,10)));
        bad(()->directInputs(keys,Arrays.copyOf(values,8)));
        Fake good=new Fake("");byte[] raw=execute(good,DIRECT_MAX);check(raw[0]==1 && good.steps.equals(Arrays.asList("construct","supported1","init","supported2","snapshot","supported3","close","artifacts","supported4")));
        for(String point:Arrays.asList("construct","init","init_false","snapshot","supported1","supported2","supported3","close","artifacts","supported4")){
            Fake bad=new Fake(point);bad(()->execute(bad,DIRECT_MAX));check(bad.steps.contains("artifacts")&&bad.steps.get(bad.steps.size()-1).startsWith("supported"));
            check(Collections.frequency(bad.steps,"close")== (bad.made?1:0));
            if(Arrays.asList("supported3","close","artifacts","supported4").contains(point))check(Arrays.equals(bad.result,new byte[3]));
            if(point.equals("close"))check(bad.steps.contains("artifacts"));
        }
        for(byte[] invalid:new byte[][]{null,new byte[0],new byte[DIRECT_MAX+1],"ERROR : synthetic".getBytes("US-ASCII")}){
            Fake invalidOp=new Fake("",invalid);bad(()->execute(invalidOp,DIRECT_MAX));check(invalidOp.steps.contains("close")&&invalidOp.steps.contains("artifacts"));
            if(invalid!=null)check(Arrays.equals(invalid,new byte[invalid.length]));
        }
        Fake linkage=new Fake("close_linkage");boolean error=false;
        try{execute(linkage,DIRECT_MAX);}catch(UnsatisfiedLinkError expected){error=true;}
        check(error&&linkage.steps.contains("artifacts")&&linkage.steps.contains("supported4")&&Arrays.equals(linkage.result,new byte[3]));
        Fake changedAfterClose=new Fake("close_error_bytes",new byte[16]);bad(()->execute(changedAfterClose,DIRECT_MAX));check(Arrays.equals(changedAfterClose.result,new byte[16]));
        String[] allKeys=Arrays.copyOf(keys,9),allValues=Arrays.copyOf(values,9);allKeys[7]="IMSI";allKeys[8]="IMEI";allValues[7]=saved;allValues[8]=saved;
        check(directInputs(allKeys,allValues).size()==9);
        check(directInputs(Arrays.copyOf(allKeys,8),Arrays.copyOf(allValues,8)).size()==8);
        allKeys[7]="IMEI";check(directInputs(Arrays.copyOf(allKeys,8),Arrays.copyOf(allValues,8)).size()==8);
        boolean immutable=false;try{parsed.put("APP_NAME",saved);}catch(UnsupportedOperationException expected){immutable=true;}check(immutable);
        System.out.println("direct_vm_boundary_selfcheck_passed rejections="+rejected);
    }
}
