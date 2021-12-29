package io.siggi.simpleecdsa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

public class ECDSASignature {
	private final SimpleECDSA simpleECDSA;
	private int v;
	private final BigInteger r, s;

	ECDSASignature(SimpleECDSA simpleECDSA, BigInteger r, BigInteger s) {
		this(simpleECDSA, -1, r, s);
	}

	ECDSASignature(SimpleECDSA simpleECDSA, int v, BigInteger r, BigInteger s) {
		this.simpleECDSA = simpleECDSA;
		if (v >= 27) v -= 27;
		if (v < -1 || v > 7) {
			throw new IllegalArgumentException("v must be between 0 and 7 or 27 and 34, or -1 if unknown");
		}
		this.v = v;
		this.r = r;
		this.s = s;
	}

	/**
	 * Get this signature's v.
	 *
	 * @return the v
	 * @throws IllegalStateException if v is unknown
	 */
	public int getV() {
		if (v == -1) {
			throw new IllegalStateException("v is unknown");
		}
		return v;
	}

	/**
	 * Get this signature's r.
	 *
	 * @return the r
	 */
	public BigInteger getR() {
		return r;
	}

	/**
	 * Get this signature's s.
	 *
	 * @return the s
	 */
	public BigInteger getS() {
		return s;
	}

	/**
	 * Set this signature's v.
	 * @param v the v
	 * @return this signature
	 * @throws IllegalStateException if v is already set
	 * @throws IllegalArgumentException if v is not valid
	 */
	public ECDSASignature setV(int v) {
		if (this.v >= 0) {
			throw new IllegalStateException("v already set");
		}
		if (v >= 27) v -= 27;
		if (v < 0 || v > 7) {
			throw new IllegalArgumentException("v must be between 0 and 7 or 27 and 34");
		}
		this.v = v;
		return this;
	}

	public byte[] toRS() {
		int bytes = simpleECDSA.getBytes();
		byte[] rBytes = ECDSAUtil.bytify(r, bytes);
		byte[] sBytes = ECDSAUtil.bytify(s, bytes);
		byte[] result = Arrays.copyOf(rBytes, rBytes.length * 2);
		System.arraycopy(sBytes, 0, result, rBytes.length, sBytes.length);
		return result;
	}

	public byte[] toRSV() {
		return toRSV(false);
	}

	public byte[] toRSV(boolean add27) {
		if (v == -1) {
			throw new IllegalStateException("v is unknown");
		}
		int bytes = simpleECDSA.getBytes();
		byte[] rBytes = ECDSAUtil.bytify(r, bytes);
		byte[] sBytes = ECDSAUtil.bytify(s, bytes);
		byte[] result = Arrays.copyOf(rBytes, (rBytes.length * 2) + 1);
		System.arraycopy(sBytes, 0, result, rBytes.length, sBytes.length);
		result[result.length - 1] = (byte) (getV() + (add27 ? 27 : 0));
		return result;
	}

	public byte[] toVRS() {
		return toVRS(false);
	}

	public byte[] toVRS(boolean add27) {
		if (v == -1) {
			throw new IllegalStateException("v is unknown");
		}
		int bytes = simpleECDSA.getBytes();
		byte[] rBytes = ECDSAUtil.bytify(r, bytes);
		byte[] sBytes = ECDSAUtil.bytify(s, bytes);
		byte[] result = new byte[(rBytes.length * 2) + 1];
		System.arraycopy(rBytes, 0, result, 1, rBytes.length);
		System.arraycopy(sBytes, 0, result, rBytes.length, sBytes.length);
		result[0] = (byte) (getV() + (add27 ? 27 : 0));
		return result;
	}

	public byte[] toDER() {
		try {
			byte[] rBytes = r.toByteArray();
			byte[] sBytes = s.toByteArray();
			ByteArrayOutputStream rs = new ByteArrayOutputStream();

			rs.write(0x02);
			ECDSAUtil.writeDerLength(rs, rBytes.length);
			rs.write(rBytes);

			rs.write(0x02);
			ECDSAUtil.writeDerLength(rs, sBytes.length);
			rs.write(sBytes);

			byte[] rsBytes = rs.toByteArray();
			ByteArrayOutputStream derSig = new ByteArrayOutputStream();
			derSig.write(0x30);
			ECDSAUtil.writeDerLength(derSig, rsBytes.length);
			derSig.write(rsBytes);
			return derSig.toByteArray();
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}
	}

	@Override
	public String toString() {
		return "ECDSASignature{r=" + r.toString(16) + ",s=" + s.toString(16) + ",v=" + (v >= 0 ? Integer.toString(v) : "?") + "}";
	}

	public static ECDSASignature fromRS(SimpleECDSA simpleEcdsa, byte[] bytes) {
		if (bytes.length % 2 != 0)
			throw new IllegalArgumentException("Invalid signature");
		int coordinateSize = bytes.length / 2;
		return new ECDSASignature(
				simpleEcdsa,
				ECDSAUtil.bigintify(Arrays.copyOfRange(bytes, 0, coordinateSize)),
				ECDSAUtil.bigintify(Arrays.copyOfRange(bytes, coordinateSize, bytes.length))
		);
	}

	public static ECDSASignature fromRSV(SimpleECDSA simpleEcdsa, byte[] bytes) {
		byte[] newBytes = new byte[bytes.length];
		System.arraycopy(bytes, 0, newBytes, 1, bytes.length - 1);
		newBytes[0] = bytes[bytes.length - 1];
		return fromVRS(simpleEcdsa, newBytes);
	}

	public static ECDSASignature fromVRS(SimpleECDSA simpleEcdsa, byte[] bytes) {
		if (bytes.length % 2 != 1)
			throw new IllegalArgumentException("Invalid signature");
		int coordinateSize = (bytes.length - 1) / 2;
		int v = bytes[0];
		return new ECDSASignature(
				simpleEcdsa,
				v,
				ECDSAUtil.bigintify(Arrays.copyOfRange(bytes, 1, coordinateSize + 1)),
				ECDSAUtil.bigintify(Arrays.copyOfRange(bytes, coordinateSize + 1, bytes.length))
		);
	}

	public static ECDSASignature fromDER(SimpleECDSA simpleEcdsa, byte[] der) {
		try {
			return fromDER(simpleEcdsa, new ByteArrayInputStream(der));
		} catch (IOException e) {
			throw new IllegalArgumentException("Invalid DER encoded signature");
		}
	}

	private static ECDSASignature fromDER(SimpleECDSA simpleEcdsa, InputStream in) throws IOException {
		int type = in.read();
		if (type != 0x30)
			throw new IllegalArgumentException("Invalid DER encoded signature");
		int dataLength = ECDSAUtil.readDerLength(in);
		byte[] data = ECDSAUtil.readBytes(in, dataLength);

		in = new ByteArrayInputStream(data);

		int rType = in.read();
		if (rType != 0x2)
			throw new IllegalArgumentException("Invalid DER encoded signature");
		int rLength = ECDSAUtil.readDerLength(in);
		byte[] r = ECDSAUtil.readBytes(in, rLength);

		int sType = in.read();
		if (sType != 0x2)
			throw new IllegalArgumentException("Invalid DER encoded signature");
		int sLength = ECDSAUtil.readDerLength(in);
		byte[] s = ECDSAUtil.readBytes(in, sLength);

		return new ECDSASignature(simpleEcdsa, ECDSAUtil.bigintify(r), ECDSAUtil.bigintify(s));
	}
}
