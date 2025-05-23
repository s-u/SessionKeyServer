// versions:
// 0.9 - private
// 1.0 - public, /pam_token
// 1.1 - /replace
// 1.2 - /auth_token (JAAS)
// 1.3 - /get_key, /gen_key, /version
// 1.4 - /create_group, /mod_group, /group_hash
// 1.5 - authentication with PAM also returns uid
package com.att.research.RCloud;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.URI;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.concurrent.Executors;
import java.security.MessageDigest;
import java.security.SecureRandom;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import com.sleepycat.je.DatabaseException;
import com.sleepycat.je.Environment;
import com.sleepycat.je.EnvironmentConfig;
import com.sleepycat.je.Database;
import com.sleepycat.je.DatabaseConfig;
import com.sleepycat.je.DatabaseEntry;
import com.sleepycat.je.LockMode;
import com.sleepycat.je.OperationStatus;

public class SessionKeyServer {
    public static final String version = "1.5";
    public static KeyStore ks;
    public static String default_module = "pam", pam_realm = null;
    public static void main(String[] args) throws IOException, KeyStoreException {
	int i = 0;
	int port = 4431;
	String bdb = null, listen = "*", tls_ks = null, tls_pwd = "SessionKeyServer";
	while (i < args.length) {
	    if (args[i].equals("-d") && ++i < args.length) bdb = args[i];
	    else if (args[i].equals("-l") && ++i < args.length) listen = args[i];
	    else if (args[i].equals("-p") && ++i < args.length) port = Integer.parseInt(args[i]);
	    else if (args[i].equals("-P") && ++i < args.length) tls_pwd = args[i];
	    else if (args[i].equals("-PF") && ++i < args.length) tls_pwd = new BufferedReader(new FileReader(args[i])).readLine();
	    else if (args[i].equals("-PP")) tls_pwd = new String(System.console().readPassword("TLS keystore+key password: "));
	    else if (args[i].equals("-tls") && ++i < args.length) tls_ks = args[i];
	    else if (args[i].equals("-default") && ++i < args.length) default_module = args[i];
	    else if (args[i].equals("-pam-app") && ++i < args.length) pam_realm = args[i];
	    else if (args[i].equals("-krb5conf") && ++i < args.length) System.setProperty("java.security.krb5.conf", args[i]);
	    else if (args[i].equals("-jaas") && ++i < args.length) System.setProperty("java.security.auth.login.config", args[i]);
	    else if (args[i].equals("-h")) {
		System.out.println("\n Usage: SessionKeyServer [-d <db-path>] [-l <address>] [-p <port>] [-pam-app <name>]\n                         [-default <module>] [-jaas <jaas.conf> [-krb5conf <krb5.conf>]]\n                         [-tls <keystore> [-P <password> | -PP]]\n\n");
		System.exit(0);
	    }
	    i++;
	}
	if (bdb != null)
	    ks = new BDBKeyStore(bdb);
	else
	    ks = new HashKeyStore();
	
	InetSocketAddress addr = listen.equals("*") ? new InetSocketAddress(port) : new InetSocketAddress(listen, port);
	HttpServer server;
	if (tls_ks != null) {
	    try {
		HttpsServer tls = HttpsServer.create(addr, 0); 
		SSLContext sslContext = SSLContext.getInstance("TLS");
		char[] password = tls_pwd.toCharArray();
		java.security.KeyStore ks = java.security.KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(tls_ks);
		ks.load(fis, password);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance ("SunX509");
		kmf.init (ks, password);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance ("SunX509");
		tmf.init (ks);
		sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		tls.setHttpsConfigurator(new HttpsConfigurator(sslContext)
		    {
			public void configure ( HttpsParameters params )
			{
			    try {
				// initialise the SSL context
				SSLContext c = SSLContext.getDefault ();
				SSLEngine engine = c.createSSLEngine ();
				params.setNeedClientAuth ( false );
				params.setCipherSuites ( engine.getEnabledCipherSuites () );
				params.setProtocols ( engine.getEnabledProtocols () );
				
				// get the default parameters
				SSLParameters defaultSSLParameters = c.getDefaultSSLParameters ();
				params.setSSLParameters ( defaultSSLParameters );
			    } catch (Exception ex) {
				System.err.println("ERROR: Failed to create HTTPS port: " + ex);
			    }
			}
		    } );
		server = tls;
	    } catch (Exception e) {
		System.err.println("Unable to create HTTPS server: "+e);
		e.printStackTrace();
		System.exit(1);
		server = null; // unreachable but the compiler can't figure it out
	    }
	} else server = HttpServer.create(addr, 0);
	
	server.createContext("/", new SKSHandler());
	server.setExecutor(Executors.newCachedThreadPool());
	server.start();
	System.out.println("SessionKeyServer " + SessionKeyServer.version +" is listening on " + listen + ":" + port);
    }
}

class KeyStoreException extends Exception {
    public KeyStoreException() { super(); }
    public KeyStoreException(String message) { super(message); }
    public KeyStoreException(String message, Throwable cause) { super(message, cause); }
    public KeyStoreException(Throwable cause) { super(cause); }
}

interface KeyStore {
    public String get(String key) throws KeyStoreException;
    public void   put(String key, String value) throws KeyStoreException;
    public void   rm(String key) throws KeyStoreException;
}

class HashKeyStore implements KeyStore {
    Map<String, String> map;

    public HashKeyStore() {
	map = new HashMap<String, String>();
    }

    public String get(String key) throws KeyStoreException {
	try {
	    return map.get(key);
	} catch (Exception e) {
	    throw new KeyStoreException("unable to retrieve key", e);
	}
    }

    public void   put(String key, String value) throws KeyStoreException {
	try {
	    map.put(key, value);
	} catch (Exception e) {
	    throw new KeyStoreException("unable to retrieve key", e);
	}
    }

    public void   rm(String key) throws KeyStoreException {
	try {
	    map.remove(key);
	} catch (Exception e) {
	    throw new KeyStoreException("unable to retrieve key", e);
	}
    }	
}

class BDBKeyStore implements KeyStore {
    Environment env;
    Database db;

    public BDBKeyStore(String path) throws KeyStoreException {
	try {
	    EnvironmentConfig envConfig = new EnvironmentConfig();
	    envConfig.setAllowCreate(true);
	    env = new Environment(new File(path), envConfig);
	    DatabaseConfig dbConfig = new DatabaseConfig();
	    dbConfig.setAllowCreate(true);
	    db = env.openDatabase(null, "sessionKeyStore", dbConfig); 
	} catch (DatabaseException dbe) {
	    throw new KeyStoreException("unable to open sessionKeyStore ("+path+") database", dbe);
	} 
    }

    public String get(String key) throws KeyStoreException {
	try {
	    DatabaseEntry theKey = new DatabaseEntry(key.getBytes("UTF-8"));
	    DatabaseEntry theData = new DatabaseEntry();
	    if (db.get(null, theKey, theData, LockMode.DEFAULT) == OperationStatus.SUCCESS)
		return new String(theData.getData(), "UTF-8");
	    return null;
	} catch (Exception e) {
	    throw new KeyStoreException("unable to store key/value pair into sessionKeyStore database", e);
	} 	
    }
    
    public void put(String key, String value) throws KeyStoreException {
	try {
	    DatabaseEntry theKey = new DatabaseEntry(key.getBytes("UTF-8"));
	    DatabaseEntry theValue = new DatabaseEntry(value.getBytes("UTF-8"));
	    db.put(null, theKey, theValue);
	    env.flushLog(false); // essentially treating puts as atomic transactions but with fsync=false we don't enforce disk I/O
	} catch (Exception e) {
	    throw new KeyStoreException("unable to store key/value pair into sessionKeyStore database", e);
	} 
    }

    public void rm(String key) throws KeyStoreException {
	try {
	    DatabaseEntry theKey = new DatabaseEntry(key.getBytes("UTF-8"));
	    db.delete(null, theKey);
	    env.flushLog(false); // essentially treating rms as atomic transactions but with fsync=false we don't enforce disk I/O
	} catch (Exception e) {
	    throw new KeyStoreException("unable to remove key from sessionKeyStore database", e);
	}
    }
}

// -- KeyStore format (key => value)  --
// t:<realm>:<token>  =>  <uid>\n<source>[\n<auxiliary data>]
// ut:<realm>:<uid>   =>  <token>
// k:<output from t:> =>  <key>
// grk:<group>        =>  <group-key>
// gr:<group>:<realm>:<user> => member|admin

class SKSHandler implements HttpHandler {
    static String bytes2hex(byte[] a) {
	StringBuilder sb = new StringBuilder();
	for(int i = 0; i < a.length; i++)
	    sb.append(String.format("%02x", a[i]));
	return sb.toString();
    }

    void respond(HttpExchange exchange, int code, String body) throws IOException {
	Headers responseHeaders = exchange.getResponseHeaders();
	responseHeaders.set("Content-Type", "text/plain");
	OutputStream responseBody = exchange.getResponseBody();
	byte outBytes[] = body.getBytes();
	exchange.sendResponseHeaders(code, outBytes.length);
	responseBody.write(outBytes);
	responseBody.close();
    }

    public void handle(HttpExchange exchange) throws IOException {
	try {
	    MessageDigest md = MessageDigest.getInstance("SHA-1");
	    MessageDigest md256 = MessageDigest.getInstance("SHA-256");
	    String requestMethod = exchange.getRequestMethod();
	    String requestPath = exchange.getRequestURI().getPath();
	    String requestQuery = exchange.getRequestURI().getRawQuery();
	    Map<String, String> queryMap = new HashMap<String, String>();  
	    if (requestQuery != null) for (String param : requestQuery.split("\\&")) {  
		    String kvp[] = param.split("=", 2);
		    if (kvp.length > 1) queryMap.put(kvp[0], java.net.URLDecoder.decode(kvp[1]));  
		}
	    if (requestMethod.equalsIgnoreCase("GET") && requestPath.equals("/version")) {
		respond(exchange, 200, SessionKeyServer.version + "\n");
		return;
	    }

	    String realm = queryMap.get("realm"), realm_txt;
	    if (realm == null) {
		respond(exchange, 400, "ERR: missing realm\n");
		exchange.close();
		return;
	    } else {
		realm_txt = realm;
		md.update(realm.getBytes());
		realm = bytes2hex(md.digest());
	    }
	    if (requestMethod.equalsIgnoreCase("GET")) {
		if (requestPath.equals("/valid")) {
		    String token = queryMap.get("token");
		    if (token != null) {
			String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
			if (val != null) {
			    String info[] = val.split("\n");
			    if (info.length > 1) {
				String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
				if (tok != null && tok.equals(token)) {
				    respond(exchange, 200, "YES\n" + val + "\n");
				    System.out.println("token: "+((new Date()).getTime())+" user='"+info[0]+"' "+info[1]+", "+realm_txt+":"+token+" {" + val.replace("\n"," ") + "}, VALID");
				    return;
				} else {
				    respond(exchange, 200, "SUPERCEDED\n" + val + "\n");
				    System.out.println("token: "+((new Date()).getTime())+" user='"+info[0]+"' "+info[1]+", "+realm_txt+":"+token+" {" + val.replace("\n"," ") + "}, SUPERCEDED");
				    return;
				}
			    }
			}
		    }
		    respond(exchange, 200, "NO\n");
		    System.out.println("token: "+((new Date()).getTime())+" "+token+", INVALID");
		    return;
                } else if (requestPath.equals("/get_key") || requestPath.equals("/gen_key")) { // key retrieval/generation
		    String token = queryMap.get("token");
		    if (token != null) {
			String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
			if (val != null) {
			    String info[] = val.split("\n");
			    if (info.length > 1) {
				String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
				if (tok != null && tok.equals(token)) {
                                    if (requestPath.equals("/gen_key")) {
                                        SecureRandom random = new SecureRandom();
                                        byte bytes[] = new byte[64]; // we generate 512-bit random keys, mostly only half is needed for AES anyway
                                        random.nextBytes(bytes);
                                        String key = bytes2hex(bytes);
                                        SessionKeyServer.ks.put("k:" + val, key);
                                        respond(exchange, 200, key);
                                        System.out.println("key generated: "+((new Date()).getTime())+" user='"+info[0]+"' "+info[1]+", "+realm_txt+":"+token+", VALID");
                                        return;
                                    }
                                    String key = SessionKeyServer.ks.get("k:" + val);
				    respond(exchange, 200, (key == null) ? "" : key);
				    System.out.println("key requested: "+((new Date()).getTime())+" user='"+info[0]+"' "+info[1]+", "+realm_txt+":"+token+", VALID, " + ((key == null) ? "ABSENT" : "PRESENT"));
				    return;
				}
			    }
			}
		    }
		    System.out.println("key: "+((new Date()).getTime())+" "+token+", INVALID");
		    exchange.sendResponseHeaders(403, -1);
		    exchange.close();
		    return;
		} else if (requestPath.equals("/replace")) {
		    String token = queryMap.get("token");
		    if (token != null) {
			String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
			if (val != null) {
			    String info[] = val.split("\n");
			    if (info.length > 1) {
				String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
				if (tok != null && tok.equals(token)) {
				    // valid token, replace
				    md.update(java.util.UUID.randomUUID().toString().getBytes());
				    md.update(java.util.UUID.randomUUID().toString().getBytes());
				    String sha1 = bytes2hex(md.digest());
				    SessionKeyServer.ks.put("t:" + realm + ":" + sha1, val);
				    SessionKeyServer.ks.put("ut:" + realm + ":" + info[0], sha1);
				    SessionKeyServer.ks.rm("t:" + realm + ":" + token);
				    respond(exchange, 200, sha1 + "\n" + val + "\n");
				    System.out.println("replace: "+((new Date()).getTime())+" user='"+info[0]+"' "+info[1]+", "+realm_txt+":"+token+"/"+sha1+", VALID");
				    return;
				}
			    }
			}
		    }
		    System.out.println("replace: "+((new Date()).getTime())+" "+token+", INVALID");
		    exchange.sendResponseHeaders(403, -1);
		    exchange.close();
		    return;
		} else if (requestPath.equals("/revoke")) {
		    String token = queryMap.get("token");
		    if (token != null) {
			String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
			if (val != null) {
			    SessionKeyServer.ks.rm("t:" + realm + ":" + token);
			    String info[] = val.split("\n");
			    if (info.length > 1) {
				String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
				if (tok != null && tok.equals(token))
				    SessionKeyServer.ks.put("ut:" + realm + ":" + info[0], "revoked");
			    }
			    System.out.println("revoked: "+((new Date()).getTime())+" user='"+info[0]+"', "+token+", VALID");
			    respond(exchange, 200, "OK\n");
			    return;
			}
		    }
		    System.out.println("token: "+((new Date()).getTime())+" "+token+", INVALID");
		    respond(exchange, 200, "INVALID\n");
		    return;
		} else if (requestPath.equals("/stored_token")) {
		    String user = queryMap.get("user");
		    String token = queryMap.get("token");
		    if (user != null && user.length() > 0 && token != null && token.length() > 0) {
			SessionKeyServer.ks.put("t:" + realm + ":" + token, user + "\nstored\n");
			SessionKeyServer.ks.put("ut:" + realm + ":" + user, token);
			respond(exchange, 200, token + "\n" + user + "\nstored\n");
			exchange.close();
			return;
		    }
		} else if (requestPath.equals("/pam_token")) { // this is for legacy - it is superceded by /auth_token
		    String user = queryMap.get("user");
		    String pwd = queryMap.get("pwd");
		    boolean succ = false;
		    UserInfo info = null;
		    if ((info = com.att.research.RCloud.PAM.checkUserWithInfo((SessionKeyServer.pam_realm == null) ? realm_txt : SessionKeyServer.pam_realm, user, pwd)) != null) {
			md.update(java.util.UUID.randomUUID().toString().getBytes());
			md.update(java.util.UUID.randomUUID().toString().getBytes());
			String sha1 = bytes2hex(md.digest());
			String sInfo = "";
			if (info != null && info.uid >= 0) sInfo = "uid="+info.uid+"\n";
			if (info != null && info.gid >= 0) sInfo += "gid="+info.gid+"\n";
			SessionKeyServer.ks.put("t:" + realm + ":" + sha1, user + "\npam\n" + sInfo);
			SessionKeyServer.ks.put("ut:" + realm + ":" + user, sha1);
			respond(exchange, 200, sha1 + "\n" + user + "\npam\n" + sInfo);
			exchange.close();
			succ = true;
		    } else {
			exchange.sendResponseHeaders(403, -1);
                        exchange.close();
		    }
		    System.out.println("PAM: "+((new Date()).getTime())+" user='"+user+"', "+realm_txt+", " + ((info == null) ? "" : info) +(succ?"OK":"FAILED"));
		} else if (requestPath.equals("/auth_token")) {
                    String user = queryMap.get("user");
                    String pwd = queryMap.get("pwd");
                    String module = queryMap.get("module") == null ? SessionKeyServer.default_module : queryMap.get("module");
                    boolean succ = false;
		    UserInfo info = null;
		    if (((module.compareToIgnoreCase("pam") == 0) &&
			 (info = com.att.research.RCloud.PAM.checkUserWithInfo((SessionKeyServer.pam_realm == null) ? realm_txt : SessionKeyServer.pam_realm, user, pwd)) != null) ||
			com.att.research.RCloud.JaasAuth.jaasLogin(user, pwd.toCharArray(), module)) {
			md.update(java.util.UUID.randomUUID().toString().getBytes());
			md.update(java.util.UUID.randomUUID().toString().getBytes());
			String sha1 = bytes2hex(md.digest());
			String sInfo = "";
			if (info != null && info.uid >= 0) sInfo = "uid="+info.uid+"\n";
			if (info != null && info.gid >= 0) sInfo += "gid="+info.gid+"\n";
			SessionKeyServer.ks.put("t:" + realm + ":" + sha1, user + "\nauth/" + module + "\n" + sInfo);
			SessionKeyServer.ks.put("ut:" + realm + ":" + user, sha1);
			respond(exchange, 200, sha1 + "\n" + user + "\nauth/" + module + "\n" + sInfo);
			exchange.close();
			succ = true;
		    } else {
			exchange.sendResponseHeaders(403, -1);
			exchange.close();
		    }
		    System.out.println("AUTH/" +  module + ": " + ((new Date()).getTime()) + " user='" + user + "', " + realm_txt + ", " + ((info == null) ? "" : info) + (succ ? "OK" : "FAILED"));
		} else if (requestPath.equals("/group_hash")) {
                    String group = queryMap.get("group");
                    String salt  = queryMap.get("salt");
                    String token = queryMap.get("token");
                    if (token != null && group != null) {
                        md.update(group.getBytes());
                        String group_sha1 = bytes2hex(md.digest());
                        String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
                        if (val != null) {
                            String info[] = val.split("\n");
                            if (info.length > 1) {
                                String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
                                if (tok != null && tok.equals(token)) {
                                    String gacc = SessionKeyServer.ks.get("gr:" + group_sha1 + ":" + realm + ":" + info[0]);
                                    if (gacc != null && (gacc.equals("admin") || gacc.equals("member"))) {
                                        String gkey = SessionKeyServer.ks.get("grk:" + group_sha1);
                                        if (gkey != null) {
                                            if (salt != null) 
                                                md256.update(salt.getBytes());
                                            md256.update("\n".getBytes());
                                            md256.update(gkey.getBytes());
                                            String sha256 = bytes2hex(md256.digest());
                                            respond(exchange, 200, sha256 + "\n");
                                            System.out.println("group_hash: "+((new Date()).getTime())+" group='"+group+"', user='"+
                                                               info[0]+"' "+info[1]+", "+realm_txt+":"+token);
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    exchange.sendResponseHeaders(403, -1);
                    exchange.close();
                    System.out.println("group_hash: "+((new Date()).getTime())+" group="+group+", "+token+", INVALID");
                    return;
                } else if (requestPath.equals("/create_group")) {
                    String group = queryMap.get("group");
                    String token = queryMap.get("token");
                    if (token != null && group != null) {
                        md.update(group.getBytes());
                        String group_sha1 = bytes2hex(md.digest());
                        String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
                        if (val != null) {
                            String info[] = val.split("\n");
                            if (info.length > 1) {
                                String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
                                if (tok != null && tok.equals(token)) {
                                    String gkey = SessionKeyServer.ks.get("grk:" + group_sha1);
                                    if (gkey != null) {
                                        respond(exchange, 403, "ERROR: group exists");
                                        exchange.close();
                                        return;
                                    }
                                    SessionKeyServer.ks.put("gr:" + group_sha1 + ":" + realm + ":" + info[0], "admin");
                                    md.update(java.util.UUID.randomUUID().toString().getBytes());
                                    md.update(java.util.UUID.randomUUID().toString().getBytes());
                                    String sha1 = bytes2hex(md.digest());
                                    SessionKeyServer.ks.put("grk:" + group_sha1, sha1);
                                    respond(exchange, 200, "OK\n");
                                    exchange.close();
                                    return;
                                }
                            }
                        }
                    }
                    exchange.sendResponseHeaders(403, -1);
                    exchange.close();
                    System.out.println("create_group: "+((new Date()).getTime())+" group="+group+", "+token+", FAILED");
                } else if (requestPath.equals("/mod_group")) {
                    String group = queryMap.get("group");
                    String token = queryMap.get("token");
                    if (token != null && group != null) {
                        md.update(group.getBytes());
                        String group_sha1 = bytes2hex(md.digest());
                        String val = SessionKeyServer.ks.get("t:" + realm + ":" + token);
                        if (val != null) {
                            String info[] = val.split("\n");
                            if (info.length > 1) {
                                String tok = SessionKeyServer.ks.get("ut:" + realm + ":" + info[0]);
                                if (tok != null && tok.equals(token)) {
                                    String gacc = SessionKeyServer.ks.get("gr:" + group_sha1 + ":" + realm + ":" + info[0]);
                                    if (gacc != null && gacc.equals("admin")) {
                                        String resp = "OK\n";
                                        String usrlist = queryMap.get("add_members");
                                        if (usrlist != null) {
                                            System.out.println("mod_group: "+((new Date()).getTime())+" group='"+group+"', user='"+
                                                               info[0]+"' "+realm_txt+", add members: " + usrlist);                                        
                                            StringTokenizer st = new StringTokenizer(usrlist, ",");
                                            while (st.hasMoreTokens()) {
                                                String usr = st.nextToken();
                                                if (!usr.equals(""))
                                                    SessionKeyServer.ks.put("gr:" + group_sha1 + ":" + realm + ":" + usr, "member");
                                            }
                                        }
                                        usrlist = queryMap.get("add_admins");
                                        if (usrlist != null) {
                                            System.out.println("mod_group: "+((new Date()).getTime())+" group='"+group+"', user='"+
                                                               info[0]+"' "+realm_txt+", add admins: " + usrlist);
                                            StringTokenizer st = new StringTokenizer(usrlist, ",");
                                            while (st.hasMoreTokens()) {
                                                String usr = st.nextToken();
                                                if (!usr.equals(""))
                                                    SessionKeyServer.ks.put("gr:" + group_sha1 + ":" + realm + ":" + usr, "admin");
                                            }
                                        }
                                        usrlist = queryMap.get("remove");
                                        if (usrlist != null) {
                                            StringTokenizer st = new StringTokenizer(usrlist, ",");
                                            System.out.println("mod_group: "+((new Date()).getTime())+" group='"+group+"', user='"+
                                                               info[0]+"' "+realm_txt+", remove: " + usrlist);
                                            while (st.hasMoreTokens()) {
                                                String usr = st.nextToken();
                                                // NOTE: we do NOT allow admin to remove himself, 
                                                if (usr.equals(info[0]))
                                                    resp = "WARN: self-removal ignored\n";
                                                else if (!usr.equals(""))
                                                    SessionKeyServer.ks.rm("gr:" + group_sha1 + ":" + realm + ":" + usr);
                                            }
                                        }
                                        respond(exchange, 200, resp);
                                        exchange.close();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    exchange.sendResponseHeaders(403, -1);
                    exchange.close();
                    System.out.println("mod_group: "+((new Date()).getTime())+" group="+group+", "+token+", FAILED");
                } else {
		    exchange.sendResponseHeaders(404, -1);
		    exchange.close();
		    return;
		}
	    } else {
		respond(exchange, 404, "Unknown path");
		exchange.close();
	    }
	} catch (java.security.NoSuchAlgorithmException noae) {
	    exchange.sendResponseHeaders(500, -1);
	    exchange.close();
	} catch (KeyStoreException kse) {
	    exchange.sendResponseHeaders(500, -1);
	    exchange.close();
	}
    }
}
