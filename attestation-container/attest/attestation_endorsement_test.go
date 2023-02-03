package attest

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func getReportedTCBAndChipID(t *testing.T) ([]byte, []byte) {
	// Get attestation report to get chip ID and reported TCB
	// Report data for test
	reportData := [REPORT_DATA_SIZE]byte{}
	for i := 0; i < REPORT_DATA_SIZE; i++ {
		reportData[i] = byte(i)
	}

	reportBytes, err := FetchAttestationReportByte(reportData)
	if err != nil {
		t.Fatalf("Fetching report failed: %v", err)
	}
	reportedTCBBytes := reportBytes[REPORTED_TCB_OFFSET : REPORTED_TCB_OFFSET+REPORTED_TCB_SIZE]
	chipIDBytes := reportBytes[CHIP_ID_OFFSET : CHIP_ID_OFFSET+CHIP_ID_SIZE]
	return reportedTCBBytes, chipIDBytes
}

func TestFetchAttestationEndorsementFromAzure(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	endorsement, err := FetchAttestationEndorsement("Azure", reportedTCBBytes, chipIDBytes)
	if err != nil || len(endorsement) == 0 {
		t.Fatalf("Fetching attestation endorsement failed: %s", err)
	}
}

func TestFetchAttestationEndorsementFromAMD(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	endorsement, err := FetchAttestationEndorsement("AMD", reportedTCBBytes, chipIDBytes)
	if err != nil || len(endorsement) == 0 {
		t.Fatalf("Fetching attestation endorsement failed: %s", err)
	}
}

func TestInvalidServer(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	server := "Invalid Server Type"
	_, err := FetchAttestationEndorsement(server, reportedTCBBytes, chipIDBytes)
	if err.Error() != fmt.Sprintf("invalid endorsement server: %s", server) {
		t.Fatalf("Should return error for invalid server")
	}
}

func TestInvalidReportedTCBBytes(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	reportedTCBBytes = []byte{}
	_, err := FetchAttestationEndorsement("Azure", reportedTCBBytes, chipIDBytes)
	if err.Error() != fmt.Sprintf("Length of reportedTCBBytes should be %d", REPORTED_TCB_SIZE) {
		t.Fatalf("Should return error for invalid length of reportedTCBBytes")
	}
}

func TestInvalidChipID(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	chipIDBytes = []byte{}
	_, err := FetchAttestationEndorsement("Azure", reportedTCBBytes, chipIDBytes)
	if err.Error() != fmt.Sprintf("Length of chipIDBytes should be %d", CHIP_ID_SIZE) {
		t.Fatalf("Should return error for invalid length of chipIDBytes")
	}
}
func TestGetAttestationEndorsementFromEnvironment(t *testing.T) {
	const testDataHostAmdCertificate = "testdata/host_amd_certificate_env"
	const envvar = DEFAULT_ENDORSEMENT_ENVVAR

	endorsement, err := os.ReadFile(testDataHostAmdCertificate)
	if err != nil {
		t.Fatalf("Could not open file %s", testDataHostAmdCertificate)
	}

	// Valid
	if os.Setenv(envvar, string(endorsement)) != nil {
		t.Fatalf("Could not set environment variable %s", envvar)
	}
	_, err = ParseEndorsementACIFromEnvironment(envvar)
	if err != nil {
		t.Fatalf("Could not parse ACI endorsement: %s", err)
	}

	// Empty
	if os.Setenv(envvar, "") != nil {
		t.Fatalf("Could not set environment variable %s", envvar)
	}
	_, err = ParseEndorsementACIFromEnvironment(envvar)
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("Could not parse ACI endorsement: %s", err)
	}

	// Invalid base64
	if os.Setenv(envvar, string(endorsement[:len(endorsement)-1])) != nil {
		t.Fatalf("Could not set environment variable %s", envvar)
	}
	_, err = ParseEndorsementACIFromEnvironment(envvar)
	if !strings.Contains(err.Error(), "illegal base64 data") {
		t.Fatalf("Could not parse ACI endorsement: %s", err)
	}

	// Invalid JSON
	if os.Setenv(envvar, string(endorsement[:len(endorsement)-4])) != nil {
		t.Fatalf("Could not set environment variable %s", envvar)
	}
	_, err = ParseEndorsementACIFromEnvironment(envvar)
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("Could not parse ACI endorsement: %s", err)
	}
}
