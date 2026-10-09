#!/bin/sh
# Real SMP 2.0 client test (SPEC section 12) with phoss smp-client, in Docker. From the repo root:
#   tests/phoss-client/run.sh                      # as a partner AP would run phoss (no HTTP redirects)
#   tests/phoss-client/run.sh -DfollowRedirects=true
set -e
ZONE=$(sed -n 's/^bdxl_zone: *\([^ #]*\).*/\1/p' config.yaml)
PARTICIPANT=${PARTICIPANT:-urn:oasis:names:tc:ebcore:partyid-type:iso6523:0192::991825827}
DOCTYPE=${DOCTYPE:-bdx-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1}
exec docker run --rm -v webuild-m2:/root/.m2 -v "$PWD":/w -w /w/tests/phoss-client maven:3.9-eclipse-temurin-21 sh -c '
  mvn -q -B compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt &&
  java -Dorg.slf4j.simpleLogger.defaultLogLevel=warn "$@" -cp target/classes:$(cat target/cp.txt) eu.webuild.smp.ClientTest '"$ZONE $PARTICIPANT $DOCTYPE /w/trust/webuild-smp-ca.pem"' 
' sh "$@"
