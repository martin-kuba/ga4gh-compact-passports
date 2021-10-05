package org.ga4gh.duri.passport;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.SignMessage;
import COSE.Signer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.google.crypto.tink.subtle.Hex;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.upokecenter.cbor.CBORObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
@Component
public class GA4GHPassportTest implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(GA4GHPassportTest.class);

    public static void main(String[] args) {
        SpringApplication.run(GA4GHPassportTest.class, args);
    }

    //keys generated at https://mkjwk.org/
    @Value("classpath:rsa_2048.jwks")
    Resource rsaKeys;

    @Value("classpath:ecc_p256.jwks")
    Resource eccKeys;

    @Value("classpath:ed25519.jwks")
    Resource okpKeys;

    @Override
    public void run(String... args) throws Exception {
        log.debug("loading JSON Web Keys Sets");
        JWK rsaKey = JWKSet.parse(new String(rsaKeys.getInputStream().readAllBytes(), StandardCharsets.UTF_8)).getKeys().get(0);
        JWK eccKey = JWKSet.parse(new String(eccKeys.getInputStream().readAllBytes(), StandardCharsets.UTF_8)).getKeys().get(0);
        JWK okpKey = JWKSet.parse(new String(okpKeys.getInputStream().readAllBytes(), StandardCharsets.UTF_8)).getKeys().get(0);
        URI jwkURL = new URI("https://login.elixir-czech.org/oidc/jwk");
        Visa visa = createExampleVisa();

        String jwtSignedWithRSA = createGA4GHPassportVisa(rsaKey, jwkURL, visa);
        log.info("visa as JWT: {}", jwtSignedWithRSA);
        log.info("JWT with RSA character length: {}", jwtSignedWithRSA.length());

        String jwtSignedWithECC = createGA4GHPassportVisa(eccKey, jwkURL, visa);
        log.info("visa as JWT: {}", jwtSignedWithECC);
        log.info("JWT with ECC character length: {}", jwtSignedWithECC.length());

        String jwtSignedWithOKP = createGA4GHPassportVisa(okpKey, jwkURL, visa);
        log.info("visa as JWT: {}", jwtSignedWithOKP);
        log.info("JWT with OKP character length: {}", jwtSignedWithOKP.length());

        CBORMapper mapper = new CBORMapper();
        ObjectWriter writer = mapper.writer();
        String jsonPayload = SignedJWT.parse(jwtSignedWithECC).getPayload().toString();
        log.info("JSON payload: {}",jsonPayload);
        log.info("JSON payload byte length: {}",jsonPayload.length());
        JsonNode payload = new ObjectMapper().readValue(jsonPayload, JsonNode.class);
        byte[] cborPayload = new CBORMapper().writer().writeValueAsBytes(payload);
        byte[] cborVisa = createCBORVisa(cborPayload);
        log.info("CBOR payload: {}", Hex.encode(cborPayload));
        log.info("CBOR payload byte length: {}",cborPayload.length);
        log.info("COSE: {}", Hex.encode(cborVisa));
        log.info("COSE byte length: {}",cborVisa.length);
    }

    private Visa createExampleVisa() {
        String issuer = "https://login.elixir-czech.org/oidc/";
        String subject = "766e0e9deb110dca86b4132485bcfe4daba72db6@elixir-europe.org";
        long asserted = System.currentTimeMillis() / 1000L;
        long expires = Instant.ofEpochSecond(asserted).atZone(ZoneId.systemDefault()).plusYears(10L).toEpochSecond();
        return new Visa(
                issuer,
                subject,
                "AcceptedTermsAndPolicies",
                "https://doi.org/10.1038/s41431-018-0219-y",
                "https://elixir-europe.org/",
                "self",
                asserted,
                expires
        );
    }

    static record Visa(String issuer, String subject, String type, String value, String source, String by, long asserted, long expires) {
    }


    private String createGA4GHPassportVisa(JWK key, URI jku, Visa visa) throws JOSEException {
        Map<String, Object> passportVisaObject = new HashMap<>();
        passportVisaObject.put("type", visa.type());
        passportVisaObject.put("asserted", visa.asserted());
        passportVisaObject.put("value", visa.value());
        passportVisaObject.put("source", visa.source());
        passportVisaObject.put("by", visa.by());
        // https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(key.getAlgorithm().getName()))
                .keyID(key.getKeyID())
                .type(JOSEObjectType.JWT)
//                .jwkURL(jku)
                .build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(visa.issuer())
                .issueTime(new Date())
                .expirationTime(new Date(visa.expires() * 1000L))
                .subject(visa.subject())
                .jwtID(UUID.randomUUID().toString())
                .claim("ga4gh_visa_v1", passportVisaObject)
                .build();
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSet);
        log.debug("signing JWT with {} key", key.getKeyType().getValue());
        JWSSigner signer = switch (key.getKeyType().getValue()) {
            case "RSA" -> new RSASSASigner(key.toRSAKey().toRSAPrivateKey());
            case "EC" -> new ECDSASigner(key.toECKey().toECPrivateKey());
            case "OKP" -> new Ed25519Signer(key.toOctetKeyPair());
            default -> null;
        };
        jwt.sign(signer);
        return jwt.serialize();
    }

    private byte[] createCBORVisa(byte[] payload) throws CoseException {
        SignMessage msg = new SignMessage();
        //  Add the content to the message
        msg.SetContent(payload);
        //  Create the signer for the message
        Signer signer = new Signer();
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        signer.setKey(key);
        msg.AddSigner(signer);
        //  Force the message to be signed
        msg.sign();
        //  Now serialize out the message
        return msg.EncodeToBytes();
    }
}
