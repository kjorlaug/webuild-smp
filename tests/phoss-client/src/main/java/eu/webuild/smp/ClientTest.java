package eu.webuild.smp;

import java.io.FileInputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.helger.peppolid.IDocumentTypeIdentifier;
import com.helger.peppolid.IParticipantIdentifier;
import com.helger.peppolid.factory.BDXR2IdentifierFactory;
import com.helger.smpclient.bdxr2.BDXR2ClientReadOnly;
import com.helger.smpclient.url.dns.BDXLURLProvider;
import com.helger.xsds.bdxr.smp2.ServiceGroupType;
import com.helger.xsds.bdxr.smp2.ServiceMetadataType;
import com.helger.xsds.bdxr.smp2.ac.EndpointType;
import com.helger.xsds.bdxr.smp2.ac.ProcessMetadataType;

/**
 * Sender-side lookup with phoss smp-client (BDXR2), as a partner AP would do it:
 * BDXL U-NAPTR discovery, ServiceGroup (through the static host's 308), ServiceMetadata,
 * XSD validation and XMLDSig verification against the WE BUILD trust anchor.
 *
 * Args: bdxlZone participant(scheme::value) documentType(scheme::value) trustAnchor.pem
 */
public final class ClientTest {
  private static int failures = 0;

  private static void check(final String name, final boolean ok, final Object detail) {
    System.out.println("[" + (ok ? "PASS" : "FAIL") + "] " + name + (detail != null ? "  - " + detail : ""));
    if (!ok)
      failures++;
  }

  public static void main(final String[] args) throws Exception {
    final String zone = args[0];
    final var idf = BDXR2IdentifierFactory.INSTANCE;
    final IParticipantIdentifier pid = idf.parseParticipantIdentifier(args[1]);
    final IDocumentTypeIdentifier did = idf.parseDocumentTypeIdentifier(args[2]);
    if (pid == null || did == null)
      throw new IllegalArgumentException("Cannot parse identifiers " + args[1] + " / " + args[2]);

    final X509Certificate ca;
    try (var in = new FileInputStream(args[3])) {
      ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
    final KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("webuild-smp-ca", ca);

    // BDXL-02: one label = base32(sha256(lower(scheme::value))), no separate scheme label
    final BDXLURLProvider bdxl = new BDXLURLProvider();
    bdxl.setAddIdentifierSchemeToZone(false);
    bdxl.setLowercaseValueBeforeHashing(true);
    System.out.println("BDXL name: " + bdxl.getDNSNameOfParticipant(pid, zone));

    final URI smp = bdxl.getSMPURIOfParticipant(pid, zone);
    check("BDXL U-NAPTR discovery (BDXL-02..04)", smp != null, smp);

    final BDXR2ClientReadOnly client = new BDXR2ClientReadOnly(smp);
    client.setTrustStore(trust);
    client.setVerifySignature(true);
    client.setXMLSchemaValidation(true);
    // phoss turns HTTP redirects off by default, as a partner AP would run it. Diagnostics only:
    if (Boolean.getBoolean("followRedirects"))
      client.withHttpClientSettings(x -> x.setFollowRedirects(true));
    if (Boolean.getBoolean("noRevocationCheck"))
      client.setRevocationCheckMode(com.helger.security.revocation.ERevocationCheckMode.NONE);

    final ServiceGroupType sg = client.getServiceGroupOrNull(pid);
    check("ServiceGroup (SMP-04)", sg != null,
          sg == null ? null : BDXR2ClientReadOnly.getAllDocumentTypes(sg, idf).size() + " service reference(s)");
    if (sg != null)
      check("ServiceGroup lists the document type", BDXR2ClientReadOnly.getAllDocumentTypes(sg, idf)
                                                                         .containsAny(did::hasSameContent), did.getURIEncoded());

    final ServiceMetadataType sm = client.getServiceMetadataOrNull(pid, did);
    check("ServiceMetadata, XSD-valid, signature verified against trust anchor (SIG)", sm != null, null);
    if (sm != null) {
      for (final ProcessMetadataType pm : sm.getProcessMetadata())
        for (final EndpointType ep : pm.getEndpoint())
        {
          check("Endpoint", ep.getAddressURIValue() != null,
                ep.getTransportProfileIDValue() + " -> " + ep.getAddressURIValue());
          // ERDS-02: ETSI EN 319 522-3 ERDSMetadata as SMP 2.0 extension, as a sending ERDS reads it
          if (ep.getSMPExtensions() != null)
            for (final var ext : ep.getSMPExtensions().getSMPExtension())
              if ("ERDSMetadata".equals(ext.getIDValue())) {
                final org.w3c.dom.Element md = (org.w3c.dom.Element) ext.getExtensionContent().getAny();
                final boolean ok = md != null && "http://uri.etsi.org/19522/v1#".equals(md.getNamespaceURI()) &&
                                   "ERDSMetadata".equals(md.getLocalName());
                check("  ERDSMetadata extension", ok, ok ? "domain " +
                      md.getElementsByTagName("ERDSDomain").item(0).getTextContent() + ", profile " +
                      md.getElementsByTagName("ERDSProfileSupported").item(0).getTextContent() : null);
              }
        }
    }

    final IParticipantIdentifier unknown = idf.createParticipantIdentifier(pid.getScheme(), "000000000");
    boolean notFound;
    try {
      notFound = new BDXR2ClientReadOnly(smp).getServiceGroupOrNull(unknown) == null;
    } catch (final Exception ex) {
      notFound = false;
    }
    check("Unknown participant -> not found (SMP-03)", notFound, null);

    System.out.println(failures == 0 ? "\nAll client checks passed" : "\n" + failures + " client check(s) failed");
    System.exit(failures == 0 ? 0 : 1);
  }
}
