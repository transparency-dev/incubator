package mtc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseAndExtract(t *testing.T) {
	// Fixed DER payload (typo fixed in validity period, and appended 00 to match outer sequence length of 330 bytes)
	derHex := "30820146a003020102301c311a3018060a2b0601040182da4b2f010c0a34343336332e34382e38301e170d3235313131313230313732365a170d3235313131383230313732365a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b4c6f7320416e67656c6573313c303a060355040a1333496e7465726e657420436f72706f726174696f6e20666f722041737369676e6564204e616d657320616e64204e756d626572733116301406035504030c0d2a2e6578616d706c652e636f6d042088c3292097527f95650a51dac5945eca168bc4bb2664c30d022036a4c47cfccea34e304c30250603551d11041e301c820d2a2e6578616d706c652e636f6d820b6578616d706c652e636f6d300e0603551d0f0101ff04040302078030130603551d25040c300a06082b0601050507030100"
	der, err := hex.DecodeString(derHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	entry, err := ParseTBSCertificateLogEntry(der)
	if err != nil {
		t.Fatalf("ParseTBSCertificateLogEntry failed: %v", err)
	}

	gotDNSNames := ExtractDNSNames(entry)
	wantDNSNames := []string{"*.example.com", "example.com"}

	if diff := cmp.Diff(wantDNSNames, gotDNSNames); diff != "" {
		t.Errorf("ExtractDNSNames mismatch (-want +got):\n%s", diff)
	}
}

func TestMTCVerifier(t *testing.T) {
	name := "oid/1.3.6.1.4.1.44363.47.1.44363.48.8"
	pubKeyB64 := "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	cosignerID := "44363.48.9"
	logID := "44363.48.8"

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode pubKey: %v", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	verifier, err := NewMTCVerifier(name, pubKey, cosignerID, logID)
	if err != nil {
		t.Fatalf("NewMTCVerifier failed: %v", err)
	}

	if verifier.Name() != name {
		t.Errorf("Name() = %q, want %q", verifier.Name(), name)
	}

	// Expected KeyHash: 0x8e6a3b1a
	wantKeyHash := uint32(0x8e6a3b1a)
	if verifier.KeyHash() != wantKeyHash {
		t.Errorf("KeyHash() = 0x%x, want 0x%x", verifier.KeyHash(), wantKeyHash)
	}

	checkpointText := `bootstrap-mtca.cloudflareresearch.com/logs/shard3
197762974
7NWRnNW49lCjHOLMyMLBYRkRTGxDhVEmQhTw2gD/Pig=`

	sigB64 := "jmo7GsZLYkXSa+C4eXII6rUTN8BECzdUogRIlzML8wqeWnFuTjOjAOGrHu79pnjuZBx1syo5FYNs5sKpj2D93QEkLws="
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	if len(sigBytes) < 4 {
		t.Fatalf("Signature too short")
	}
	rawSig := sigBytes[4:]

	if !verifier.Verify([]byte(checkpointText), rawSig) {
		t.Error("Verification failed")
	}
}
