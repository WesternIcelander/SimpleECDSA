package io.siggi.simpleecdsa;

import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;

public class ECDSAUtil {
	private ECDSAUtil() {
	}

	private static final char[] hexSet = "0123456789abcdef".toCharArray();

	public static String hex(byte[] data) {
		char[] chars = new char[data.length * 2];
		for (int i = 0; i < data.length; i++) {
			chars[i * 2] = hexSet[(data[i] >> 4) & 0xf];
			chars[i * 2 + 1] = hexSet[data[i] & 0xf];
		}
		return new String(chars);
	}

	public static byte[] unhex(String hex) {
		int length = hex.length();
		if (length % 2 != 0)
			throw new IllegalArgumentException("Invalid hex string");
		length /= 2;
		try {
			byte[] data = new byte[length];
			for (int i = 0; i < length; i++) {
				data[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
			}
			return data;
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException("Invalid hex string");
		}
	}

	static BigInteger bigintify(byte[] value) {
		return new BigInteger(1, value);
	}

	static byte[] bytify(BigInteger value, int bytes) {
		byte[] result = value.toByteArray();
		if (result.length < bytes) {
			// too short, pad with 0's in front
			byte[] newResult = new byte[bytes];
			System.arraycopy(result, 0, newResult, newResult.length - result.length, result.length);
			return newResult;
		} else if (result.length > bytes) {
			// too long, remove the beginning bytes
			return Arrays.copyOfRange(result, result.length - bytes, result.length);
		}
		return result;
	}

	static int readDerLength(InputStream in) throws IOException {
		int length = in.read();
		if (length == -1) throw new EOFException();
		if (length >= 128) {
			if (length == 128) {
				throw new UnsupportedEncodingException("Indefinite length");
			}
			int octetCount = length - 128;
			length = 0;
			for (int i = 0; i < octetCount; i++) {
				length <<= 8;
				int value = in.read();
				if (value == -1) throw new EOFException();
				length += value;
			}
		}
		return length;
	}

	static void writeDerLength(OutputStream out, int value) throws IOException {
		if (value < 0)
			throw new IllegalArgumentException("Negative number");
		if (value < 128) {
			out.write(value);
			return;
		}
		byte[] data = new byte[4];
		int start = 4;
		do {
			start -= 1;
			data[start] = (byte) (value & 0xff);
			value >>>= 8;
		} while (value != 0);
		int length = 4 - start;
		out.write(length + 128);
		out.write(data, start, length);
	}

	static byte[] readBytes(InputStream in, int bytes) throws IOException {
		byte[] b = new byte[bytes];
		int read = 0;
		int c;
		while (read < bytes) {
			c = in.read(b, read, bytes - read);
			if (c == -1) {
				throw new EOFException();
			}
			read += c;
		}
		return b;
	}
}
