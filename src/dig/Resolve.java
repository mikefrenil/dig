package dig;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
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

	public void query(String name, int type) throws TextParseException, UnknownHostException {
		
		Name query = Name.fromString(name);
		
		SimpleResolver resolver = new SimpleResolver();
		InetAddress rootServer = rootServers[(int) (Math.random() * rootServers.length)];
		System.out.println(rootServer);
		resolver.setAddress(rootServer);
		resolver.setTCP(true);
		Lookup.setDefaultResolver(resolver);
		
		ExtendedResolver er = new ExtendedResolver();
	    er.addResolver(resolver);
		
	    String curr = "";
		
		for(int j=query.labels()-1; j>=0 ; j--){
			curr = "co.jp.";//query.getLabelString(j) + "." + curr; 
			
			Lookup lookup; 
			
			if(j == 0){
				lookup = new Lookup(curr, type);	
			}
			else{
				lookup = new Lookup(curr, Type.ANY);	
			}
			
			lookup.setResolver(er);
			Record[] records = lookup.run();
			
			for(Name alias: lookup.getAliases())
				System.out.println(alias.toString());
			
			
			
			if(lookup.getResult() == Lookup.SUCCESSFUL){
				System.out.print("...");
				System.out.println(records[records.length-1].getType());
				
				if(j == 0)
				{
					System.out.println();
					for (int i = 0; i < records.length; i++) {
						Record record = (Record)records[i];
						System.out.println(record.toString());
					}
					break;
				}
				
				
			
			resolver = new SimpleResolver();
			//resolver.setAddress(InetAddress.getByName("root.dns.jp"));//lookup.getAnswers()[0].rdataToString()));
			//System.out.println(InetAddress.getByName(lookup.getAnswers()[0].rdataToString()));
			
			//System.out.println(records[0].getAdditionalName());
			
			er = new ExtendedResolver();
			er.addResolver(resolver);
				
			}
			else{
				System.err.print("\nlookup failed(");
				switch(lookup.getResult()){
					case Lookup.HOST_NOT_FOUND:
						System.err.print("host not found");
						break;
					case Lookup.TRY_AGAIN:
						System.err.print("try again");
						break;
					case Lookup.TYPE_NOT_FOUND:
						System.err.print("type not found");
						break;
					case Lookup.UNRECOVERABLE:
						System.err.print("unrecoverable");
						break;
				}
				
				System.err.println(")");
				break;
			}
		}
	}
	

}
