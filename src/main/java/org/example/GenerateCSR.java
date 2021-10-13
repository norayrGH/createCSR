package org.example;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class GenerateCSR {

  public static void main(String[] args) throws Exception {
    Provider bc = new BouncyCastleProvider();
    Security.insertProviderAt(bc, 1);
    BouncyCastleProvider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", prov.getName());
    generator.initialize(ecSpec, new SecureRandom());
    KeyPair pair = generator.generateKeyPair();
    PublicKey publicKey = pair.getPublic();
    PrivateKey privateKey = pair.getPrivate();
    X500NameBuilder subject = new X500NameBuilder();
    Extension subjectAltName = new Extension(MicrosoftObjectIdentifiers.microsoftCertTemplateV1, false,
        new BEROctetString("..TSTZATCA-Code-Signing".getBytes()));
    subject.addRDN(BCStyle.OU, "Innovation");
    subject.addRDN(BCStyle.C, "SA");
    subject.addRDN(BCStyle.O, "Amerah");
    subject.addRDN(BCStyle.OU, "IT");
    subject.addRDN(BCStyle.CN, "171.12.3.2");
    subject.addRDN(BCStyle.SERIALNUMBER, "123456");
    subject.addRDN(BCStyle.COUNTRY_OF_RESIDENCE, "SA");
    subject.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, "343556379200003");
    X500Name x500 = subject.build();
    ContentSigner signGen = new JcaContentSignerBuilder("SHA256WITHECDSA").build(privateKey);
    PKCS10CertificationRequestBuilder certificateBuilder = new JcaPKCS10CertificationRequestBuilder(x500,
        publicKey);
    certificateBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new Extensions(subjectAltName))
        .build(signGen);
    PKCS10CertificationRequest request = certificateBuilder.build(signGen);
    OutputStreamWriter output = new OutputStreamWriter(new FileOutputStream("csrGen/csr/csr.csr"));
    try (JcaPEMWriter pem = new JcaPEMWriter(output)){
      pem.writeObject(request);
    }
  }
}
