package com.meteor.common.crypto.other;

import java.security.MessageDigest;

/**
 * 说明：MD5处理
 * @author meteor
 */
public class MD5 {

	public static String md5(String str) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(str.getBytes());
		byte[] b = md.digest();

		int i;
		StringBuilder buf = new StringBuilder("");
		for (byte value : b) {
			i = value;
			if (i < 0) {
				i += 256;
			}
			if (i < 16) {
				buf.append("0");
			}
			buf.append(Integer.toHexString(i));
		}
		return buf.toString();
	}
}
