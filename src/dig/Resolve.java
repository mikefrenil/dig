package dig;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;

import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Options;
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
		
		Message lookup, result; 
			
	    Record lookupRecord = Record.newRecord(name, Type.A, DClass.IN);
			
	    
		
		Record secRecord = Record.newRecord(name, Type.DNSKEY, DClass.IN);
		
	    lookup = Message.newQuery(lookupRecord);	
		result = resolver.send(lookup);
				
		while(result.getSectionArray(Section.ANSWER).length == 0){
			
			Record[] records = result.getSectionArray(Section.AUTHORITY);
			
			if(records.length <= 1){
				System.err.println("lookup failed(host not found)");
				return;
			}
			
			for (int i = 0; i < records.length; i++) {
				Record record = (Record)records[i];
				System.out.println(record.toString());
			}
			System.out.println("....");
						
			resolver = new SimpleResolver(records[1].rdataToString());
			result = resolver.send(lookup);
			
		}
		
		lookupRecord = Record.newRecord(name, Type.ANY, DClass.IN);
			
		lookup = Message.newQuery(lookupRecord);	
		result = resolver.send(lookup);
		
		Record[] records = result.getSectionArray(Section.ANSWER);
		
		if(records[records.length-1].getType() == Type.CNAME){
			System.out.println("here");
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
		
		if(recordFound) {
			System.out.println("lookup success");
		}
		else {
			System.err.println("lookup failed(type not found)");
		}
		
	}
	

}
