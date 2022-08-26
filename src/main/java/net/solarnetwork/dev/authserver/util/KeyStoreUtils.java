/* ==================================================================
 * KeyStoreUtils.java - 27/08/2022 10:31:07 am
 * 
 * Copyright 2022 SolarNetwork.net Dev Team
 * 
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
 * 02111-1307 USA
 * ==================================================================
 */

package net.solarnetwork.dev.authserver.util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * KeyStore utility functions.
 * 
 * @author matt
 * @version 1.0
 */
public final class KeyStoreUtils {

	private KeyStoreUtils() {
		// not available
	}

	/**
	 * Generate a new key pair.
	 * 
	 * @return the key pair
	 * @throws RuntimeException
	 *         if any error occurs
	 */
	public static KeyPair generateRsaKey() {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch ( NoSuchAlgorithmException e ) {
			throw new RuntimeException("Error generating key pair", e);
		}
		keyPairGenerator.initialize(2048);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Load a KeyStore from a path, creating a new empty store if the path does
	 * not exist.
	 * 
	 * @param path
	 *        the path
	 * @param password
	 *        the password
	 * @return the store
	 * @throws RuntimeException
	 *         if any error occurs
	 */
	public static KeyStore loadKeyStore(Path path, String password) {
		if ( password == null ) {
			password = "";
		}
		try {
			if ( Files.exists(path) ) {
				return KeyStore.getInstance(path.toFile(), password.toCharArray());
			} else {
				KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
				store.load(null);
				return store;
			}
		} catch ( Exception e ) {
			throw new RuntimeException("Error loading key store from [%s]".formatted(path), e);
		}
	}

	/**
	 * Save a {@code KeyStore} to a file.
	 * 
	 * @param keyStore
	 *        the store to save
	 * @param password
	 *        the password to use
	 * @param path
	 *        the path to write to
	 * @throws RuntimeException
	 *         if any error occurs
	 */
	public static void saveKeyStore(KeyStore keyStore, String password, Path path) {
		if ( password == null ) {
			password = "";
		}
		if ( !Files.isDirectory(path.getParent()) ) {
			try {
				Files.createDirectories(path.getParent());
			} catch ( IOException e ) {
				throw new RuntimeException(
						"Error creating path [%s] for key store".formatted(path.getParent()), e);
			}
		}
		try (var out = new FileOutputStream(path.toFile())) {
			keyStore.store(out, password.toCharArray());
		} catch ( Exception e ) {
			throw new RuntimeException("Error saving key store to [%s]".formatted(path), e);
		}
	}

	/**
	 * Create a self-signed certificate.
	 * 
	 * @param keyPair
	 *        the key pair
	 * @param subjectDN
	 *        the subject
	 * @return the certificate
	 * @throws RuntimeException
	 *         if any error occurs
	 */
	public static Certificate createSignedCertificate(KeyPair keyPair, String subjectDN) {
		try {
			Provider bcProvider = new BouncyCastleProvider();
			//Security.addProvider(bcProvider);

			Instant now = Instant.now();
			Instant expire = now.plus(365 * 99, ChronoUnit.DAYS);

			X500Name dnName = new X500Name(subjectDN);
			BigInteger certSerialNumber = new BigInteger(Long.toString(now.toEpochMilli()));

			String signatureAlgorithm = "SHA256WithRSA";

			ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
					.build(keyPair.getPrivate());

			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName,
					certSerialNumber, Date.from(now), Date.from(expire), dnName, keyPair.getPublic());

			BasicConstraints basicConstraints = new BasicConstraints(true);

			certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

			return new JcaX509CertificateConverter().setProvider(bcProvider)
					.getCertificate(certBuilder.build(contentSigner));
		} catch ( Exception e ) {
			throw new RuntimeException("Error creating self-signed certificate", e);
		}
	}
}
