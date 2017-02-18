package dig;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;

import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class Resolve {
	
	InetAddress[] rootServers;
	
	public Resolve(){
		Lookup lookup = null;
		
		try {
			lookup = new Lookup(".", Type.NS);
		} catch (TextParseException e) {
			e.printStackTrace();
		}
		
		Record [] records = lookup.run();
		rootServers = new InetAddress[records.length];
		
		for (int i = 0; i < records.length; i++) {
			try {
				rootServers[i] = InetAddress.getByName(records[i].rdataToString());
			} catch (UnknownHostException e) {
				System.err.println(e.getMessage());;
			}
		}
	}
	
	public InetAddress getRootServer(){
		InetAddress rootServer = rootServers[(int) (Math.random() * rootServers.length)];
		
		return rootServer;
		
	}

	public void query(String in, int type) throws IOException {
		
		Name name = Name.fromString(in);
		
		SimpleResolver resolver = new SimpleResolver();
		InetAddress rootServer = rootServers[(int) (Math.random() * rootServers.length)];
		System.out.println(rootServer);
		resolver.setAddress(rootServer);
		resolver.setTCP(true);
		resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
		resolver.setTimeout(10);
		
		Message lookup, result; 
			
	    Record lookupRecord = Record.newRecord(name, Type.ANY, DClass.IN);
	    
	    lookup = Message.newQuery(lookupRecord);	
		result = resolver.send(lookup);
				
		while(result.getSectionArray(Section.ANSWER).length == 0){
			
			Record[] records = result.getSectionArray(Section.AUTHORITY);
			
			if(records.length <= 1){
				System.err.println("lookup failed(host not found)");
				return;
			}
			String next = null;
			
			
			for (int i = 0; i < records.length; i++) {
				Record record = (Record)records[i];
				
				if(record.getType() == Type.NS){
					next = record.rdataToString();
				}
				//System.out.println(record.toString());
			}
			
			boolean dnsVerified = dnssecVerify(result, resolver, Section.AUTHORITY);
			
			if(!dnsVerified){
				System.out.println("DNSSEC verification failed.");
				return;
			}
						
		    resolver.setAddress(InetAddress.getByName((next)));
			result = resolver.send(lookup);
			
		}
		
		Record[] records = result.getSectionArray(Section.ANSWER);
		
		if(records.length == 0){
			System.err.println("lookup failed(host not found)");
			return;
		}
		
		if(records[records.length-1].getType() == Type.CNAME){
			query(records[records.length-1].rdataToString() ,type);
			return;
		}
		
		boolean recordFound = false;
		for (int i = 0; i < records.length; i++) {
			Record record = (Record)records[i];
			if(record.getType() == type || type == Type.ANY){
				System.out.println(record.toString());
				recordFound = true;
			}
		}
		
		//System.out.println(dnssecVerify(result, resolver, Section.ANSWER));
		
		
		if(recordFound) {
			System.out.println("lookup success");
		}
		else {
			System.err.println("lookup failed(type not found)");
		}
		
	}
	
	boolean dnssecVerify(Message result, Resolver resolver, int section) throws IOException{
		
		boolean keyVerified = false;
		RRset[] rrsets = result.getSectionRRsets(section);
		//System.out.println("RRset size("+result.getSectionRRsets(Section.AUTHORITY).length+")");
		
	    for(RRset rrset : rrsets){
	    	//System.out.println(rrset);
	    	Iterator<RRSIGRecord> iter = rrset.sigs();//sigs();
	    	
	    	while(iter.hasNext()){
	    		RRSIGRecord rrsig = (RRSIGRecord) iter.next();
	    		//System.err.println(rrsig);
	    		
	    		
	    		int footprint = rrsig.getFootprint();
	    		Record signerRecord = Record.newRecord(rrsig.getSigner(), Type.DNSKEY, DClass.IN);
	            Message signerQuery = Message.newQuery(signerRecord);
	            Message signerResult = resolver.send(signerQuery);
	            Record[] signerRecords = signerResult.getSectionArray(Section.ANSWER);
	            
	            for(Record key : signerRecords)
	            {
	            	//System.err.println("KEY: "+key);
					try {
						if(key.getType() != Type.DNSKEY) continue;
						if(((DNSKEYRecord)key).getFootprint() == footprint){
							DNSSEC.verify(rrset, rrsig, (DNSKEYRecord)key);
							keyVerified = true;
						}
					}
					catch (DNSSECException e) {
						// TODO Auto-generated catch block
						System.err.println(e.getMessage());
						keyVerified = false;
					}
	            }
	    	}
	    }
		return keyVerified;
	}
	

}
