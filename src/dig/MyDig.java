package dig;

import java.io.IOException;

import org.xbill.DNS.Type;


/*
HOST_NOT_FOUND 	3
SUCCESSFUL 	0
TRY_AGAIN 	2
TYPE_NOT_FOUND 	4
UNRECOVERABLE 	1
*/
public class MyDig {
	
	

	public static void main(String[] args) {
		
		Resolve resolve = new Resolve();
		//resolve.query("www.google.co.jp.", Type.ANY);
		int type;
		
		if(args[1].equals("NS")) type = Type.NS;
		else if(args[1].equals("A")) type = Type.A;
		else if(args[1].equals("MX")) type = Type.MX;
		else {
			System.out.println("Type input invalid. Type resolved to default(ANY)");
			type = Type.ANY;
		}
		
		
		try {
			resolve.query(args[0]+".", type);
		} catch (IOException e) {
			System.err.println("lookup failed");
		}
		
	}

}
