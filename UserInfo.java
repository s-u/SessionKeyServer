// Verify user credentials against PAM
package com.att.research.RCloud;

public class UserInfo {
    public long   uid, gid;
    public String name;

    public UserInfo(String name, long uid, long gid) {
	this.name = name;
	this.uid  = uid;
	this.gid  = gid;
    }
    public UserInfo(String name) { this(name, -1, -1); }

    public String toString() {
	return "{ user='" + name + "', uid=" + uid + " gid=" + gid +" }";
    }
}
