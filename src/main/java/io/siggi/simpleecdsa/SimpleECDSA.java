package io.siggi.simpleecdsa;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static io.siggi.simpleecdsa.ECDSAUtil.bigintify;
import static io.siggi.simpleecdsa.ECDSAUtil.bytify;

public class SimpleECDSA {

	static {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

	private static final Map<String, SimpleECDSA> curves = new HashMap<>();
	private static final ReentrantReadWriteLock curvesMapLock = new ReentrantReadWriteLock();
	private static final ReentrantReadWriteLock.ReadLock curvesMapRead = curvesMapLock.readLock();
	private static final ReentrantReadWriteLock.WriteLock curvesMapWrite = curvesMapLock.writeLock();

	public static SimpleECDSA getCurve(String curve) throws InvalidAlgorithmParameterException {
		curvesMapRead.lock();
		try {
			SimpleECDSA simpleEcdsa = curves.get(curve);
			if (simpleEcdsa != null)
				return simpleEcdsa;
		} finally {
			curvesMapRead.unlock();
		}
		curvesMapWrite.lock();
		try {
			SimpleECDSA simpleEcdsa = curves.get(curve);
			if (simpleEcdsa != null)
				return simpleEcdsa;
			curves.put(curve, simpleEcdsa = new SimpleECDSA(curve));
			return simpleEcdsa;
		} finally {
			curvesMapWrite.unlock();
		}
	}

	private static final SecureRandom sharedRandom = new SecureRandom();
	private final String curve;
	private final int bits;
	private final KeyPairGenerator keyPairGenerator;
	private final KeyFactory keyFactory;
	private final ECParameterSpec ecParameterSpec;
	private final X9ECParameters params;
	private final org.bouncycastle.jce.spec.ECParameterSpec bcEcParameterSpec;

	private SimpleECDSA(String curve) throws InvalidAlgorithmParameterException {
		this.curve = curve;
		ECGenParameterSpec genParameterSpec = new ECGenParameterSpec(curve);
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
		keyPairGenerator.initialize(genParameterSpec, sharedRandom);
		this.ecParameterSpec = ((ECPrivateKey) keyPairGenerator.generateKeyPair().getPrivate()).getParams();
		this.bits = ecParameterSpec.getCurve().getField().getFieldSize();
		this.params = SECNamedCurves.getByName(curve);
		this.bcEcParameterSpec = ECNamedCurveTable.getParameterSpec(curve);
	}

	/**
	 * Get the name of the curve.
	 *
	 * @return the name of the curve
	 */
	public String getCurve() {
		return curve;
	}

	/**
	 * Get the number of bits on the curve.
	 *
	 * @return the number of bits on the curve.
	 */
	public int getBits() {
		return bits;
	}

	/**
	 * Get the number of bytes used to store coordinate information such as for public and private keys, and signature information.
	 *
	 * @return the number of bytes used to store coordinate information.
	 */
	public int getBytes() {
		return (bits + 7) / 8;
	}

	/**
	 * Generate a key pair on this curve.
	 *
	 * @return the generated key pair
	 */
	public KeyPair generateKeyPair() {
		return generateKeyPair(null);
	}

	/**
	 * Generate a key pair with a specified SecureRandom on this curve.
	 *
	 * @param random the SecureRandom to use
	 * @return the generated key pair
	 */
	public KeyPair generateKeyPair(SecureRandom random) {
		try {
			if (random == null) {
				random = sharedRandom;
			}
			KeyPairGenerator gen;
			if (random == sharedRandom) {
				gen = keyPairGenerator;
			} else {
				gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
				gen.initialize(ecParameterSpec, random);
			}
			return gen.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Encode a private key to a byte array.
	 *
	 * @param privateKey the private key to encode
	 * @return the private key as a byte array
	 */
	public byte[] toBytes(ECPrivateKey privateKey) {
		return bytify(privateKey.getS(), getBytes());
	}

	/**
	 * Encode a public key as uncompressed format to a byte array. The first byte will be 0x4, followed by the
	 * x coordinate and then the y coordinate.
	 *
	 * @param publicKey the public key to encode
	 * @return the public key as a byte array
	 */
	public byte[] toBytes(ECPublicKey publicKey) {
		return toBytes(publicKey, false);
	}

	/**
	 * Encode a public key to a byte array in compressed or uncompressed form.
	 *
	 * @param publicKey  the public key to encode
	 * @param compressed whether you want it compressed
	 * @return the public key as a byte array
	 */
	public byte[] toBytes(ECPublicKey publicKey, boolean compressed) {
		org.bouncycastle.math.ec.ECPoint point = bcEcParameterSpec.getCurve().createPoint(
				publicKey.getW().getAffineX(),
				publicKey.getW().getAffineY()
		);
		return point.getEncoded(compressed);
	}

	/**
	 * Decode a private key from a byte array.
	 *
	 * @param key the private key byte array
	 * @return the private key
	 */
	public ECPrivateKey getPrivate(byte[] key) {
		return getPrivate(bigintify(key));
	}

	/**
	 * Decode a private key from a BigInteger.
	 *
	 * @param key the private key BigInteger
	 * @return the private key
	 */
	public ECPrivateKey getPrivate(BigInteger key) {
		try {
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(key, ecParameterSpec);
			return (ECPrivateKey) keyFactory.generatePrivate(ecPrivateKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	private byte[] decompressKey(byte[] key) {
		org.bouncycastle.math.ec.ECPoint point = bcEcParameterSpec.getCurve().decodePoint(key);
		return point.getEncoded(false);
	}

	/**
	 * Decode a public key from a byte array.
	 *
	 * @param key the public key byte array
	 * @return the public key
	 */
	public ECPublicKey getPublic(byte[] key) {
		if (key.length == getBytes() * 2) {
			byte[] newKey = new byte[key.length + 1];
			newKey[0] = 0x4;
			System.arraycopy(key, 0, newKey, 1, key.length);
			key = newKey;
		}
		if (key[0] == 0x2 || key[0] == 0x3) {
			key = decompressKey(key);
		} else if (key[0] != 0x4) {
			throw new IllegalArgumentException("Invalid public key");
		}
		int pointSize = (key.length - 1) / 2;
		BigInteger x = bigintify(Arrays.copyOfRange(key, 1, 1 + pointSize));
		BigInteger y = bigintify(Arrays.copyOfRange(key, 1 + pointSize, 1 + (2 * pointSize)));
		return getPublic(x, y);
	}

	/**
	 * Decode a public key from it's x and y coordinate BigIntegers.
	 *
	 * @param x the x coordinate
	 * @param y the y coordinate
	 * @return the public key
	 */
	public ECPublicKey getPublic(BigInteger x, BigInteger y) {
		if (x == null || y == null) throw new NullPointerException();
		try {
			ECPoint point = new ECPoint(x, y);
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
			return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Derive a public key from a private key.
	 *
	 * @param privateKey the private key
	 * @return the public key
	 */
	public ECPublicKey getPublic(ECPrivateKey privateKey) {
		BigInteger privKey = privateKey.getS();
		ECParameterSpec params = privateKey.getParams();
		BigInteger order = params.getOrder();
		if (privKey.bitLength() > order.bitLength()) {
			privKey = privKey.mod(order);
		}

		org.bouncycastle.math.ec.ECPoint point = (new FixedPointCombMultiplier()).multiply(this.params.getG(), privKey);
		byte[] encoded = point.getEncoded(false);
		return getPublic(encoded);
	}

	/**
	 * Recover the public key from a signature and message. v must be set on the signature.
	 *
	 * @param signature the signature
	 * @param message   the hash of the message
	 * @return the public key
	 */
	public ECPublicKey recover(ECDSASignature signature, byte[] message) {
		return recover(signature.getR(), signature.getS(), signature.getV(), message);
	}

	/**
	 * Recover the public key from a signature.
	 *
	 * @param r       the r
	 * @param s       the s
	 * @param v       the v
	 * @param message the hash of the message
	 * @return the public key
	 */
	public ECPublicKey recover(BigInteger r, BigInteger s, int v, byte[] message) {
		BigInteger modifiedR = r;
		int orderMultiplier = (v >> 1);
		if (orderMultiplier > 0) {
			modifiedR = modifiedR.add(params.getN().multiply(new BigInteger(Integer.toString(orderMultiplier))));
		}

		byte[] compressedR = bytify(modifiedR, 1 + ((params.getCurve().getFieldSize() + 7) / 8));
		compressedR[0] = (byte) (2 + (v & 0x1));
		org.bouncycastle.math.ec.ECPoint R = params.getCurve().decodePoint(compressedR);
		if (R == null || !R.multiply(params.getN()).isInfinity())
			throw new IllegalArgumentException("Invalid signature");
		BigInteger e = bigintify(message);
		BigInteger eInv = BigInteger.ZERO.subtract(e).mod(params.getN());
		BigInteger rInv = r.modInverse(params.getN());
		BigInteger srInv = rInv.multiply(s).mod(params.getN());
		BigInteger eInvrInv = rInv.multiply(eInv).mod(params.getN());
		org.bouncycastle.math.ec.ECPoint q = ECAlgorithms.sumOfTwoMultiplies(params.getG(), eInvrInv, R, srInv);
		if (q.isInfinity())
			throw new IllegalArgumentException("Invalid signature");
		return getPublic(q.getEncoded(false));
	}

	/**
	 * Sign a message.
	 *
	 * @param key     the private key to sign with
	 * @param message the message hash to sign
	 * @return the signature
	 */
	public ECDSASignature sign(ECPrivateKey key, byte[] message) {
		try {
			Signature sig = Signature.getInstance("NONEwithECDSA");
			sig.initSign(key);
			sig.update(message);
			ECDSASignature signature = ECDSASignature.fromDER(this, sig.sign());
			ECPublicKey expectedPublic = getPublic(key);
			for (int v = 0; v < 8; v++) {
				try {
					ECPublicKey actualPublic = recover(signature.getR(), signature.getS(), v, message);
					if (actualPublic.equals(expectedPublic)) {
						return signature.setV(v);
					}
				} catch (Exception e) {
				}
			}
			return signature;
		} catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Verify a signature matches a public key and message
	 *
	 * @param key       the public key
	 * @param message   the message hash
	 * @param signature the signature
	 * @return true if the signature is valid
	 */
	public boolean verify(ECPublicKey key, byte[] message, ECDSASignature signature) {
		try {
			Signature sig = Signature.getInstance("NONEwithECDSA");
			sig.initVerify(key);
			sig.update(message);
			return sig.verify(signature.toDER());
		} catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}
}
