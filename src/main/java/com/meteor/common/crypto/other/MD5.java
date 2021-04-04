package com.meteor.common.crypto.other;

import java.security.MessageDigest;

/**
 * @Description: MD5
 * @ClassName: MD5
 * @author: meteor
 * @createDate: 2021年04月03日
 * <p>
 * ---------------------------------------------------------
 * Version  v1.0
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
