package org.example;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

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
		X500Principal subject = new X500Principal("C=NO, ST=Trondheim, L=Trondheim, O=Senthadev, OU=Innovation, CN=www.senthadev.com, EMAILADDRESS=senthadev@gmail.com",
				Map.of("OID",
						"1.3.6.1.4.1.311.21.8.2200605.9715090.14372516.15973785.1368149.102.15135184.3454480"));
		PKCS10CertificationRequestBuilder certificateBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
		PKCS10CertificationRequest request = certificateBuilder.build(signGen);
		StringWriter writer = new StringWriter();
		PemWriter pemWriter = new PemWriter(writer);
		pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", request.getEncoded()));
		pemWriter.flush();
		pemWriter.close();
	}
}
