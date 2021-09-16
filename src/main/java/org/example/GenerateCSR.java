package org.example;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.security.auth.x500.X500Principal;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class GenerateCSR {

	public static void main(String a[]) throws Exception{
		//loading the BC provider and setting it as a default provider
		Provider bc = new BouncyCastleProvider();
		Security.insertProviderAt(bc, 1);

		BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);
		// View supported Providers and Algorithms
		// Generate ECDSA public and private keys
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", prov.getName());
		generator.initialize(ecSpec, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();
		PublicKey publicKey = pair.getPublic();
		PrivateKey privateKey = pair.getPrivate();

		
		//http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs
		ContentSigner signGen = new JcaContentSignerBuilder("SHA1withECDSA").build(privateKey);
		
		X500Principal subject = new X500Principal("C=NO, ST=Trondheim, L=Trondheim, O=Senthadev, OU=Innovation, CN=www.senthadev.com, EMAILADDRESS=senthadev@gmail.com");
		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
		PKCS10CertificationRequest request = builder.build(signGen);
		OutputStreamWriter output = new OutputStreamWriter(System.out);
		PEMWriter pem = new PEMWriter(output);
		pem.writeObject(request);
		pem.close();
	}
}
