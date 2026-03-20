package synapse

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"time"

	engine "github.com/synapse/engine"
)

// ============================================================================
// CSV Output
// ============================================================================

// WriteCSV writes findings as CSV rows to the given writer.
// Header: file,line,detector,confidence,provenance,matched_value,description
func WriteCSV(findings []engine.Finding, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"file", "line", "detector", "confidence", "provenance",
		"matched_value", "description",
	}); err != nil {
		return err
	}

	for _, f := range findings {
		if err := cw.Write([]string{
			f.File,
			fmt.Sprintf("%d", f.Line),
			f.Detector,
			fmt.Sprintf("%.4f", f.Confidence),
			f.Provenance,
			f.MatchedValue,
			f.ReasoningStr,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// JUnit XML Output
// ============================================================================

// JUnitTestSuites is the top-level JUnit XML structure.
type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a single test suite.
type JUnitTestSuite struct {
	XMLName  xml.Name        `xml:"testsuite"`
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Time     float64         `xml:"time,attr"`
	Cases    []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a single test case (finding or pass).
type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

// JUnitFailure represents a test failure.
type JUnitFailure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
	Content string   `xml:",chardata"`
}

// WriteJUnit writes findings as JUnit XML to the given writer.
// Each finding becomes a failed test case in the "morphex-secret-scan" suite.
func WriteJUnit(findings []engine.Finding, elapsed time.Duration, w io.Writer) error {
	suite := JUnitTestSuite{
		Name:     "morphex-secret-scan",
		Tests:    len(findings),
		Failures: len(findings),
		Time:     elapsed.Seconds(),
	}

	for _, f := range findings {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("%s:%d", f.File, f.Line),
			ClassName: f.Detector,
			Time:      0,
			Failure: &JUnitFailure{
				Message: fmt.Sprintf("Secret found: %s (%.0f%% confidence)", f.Provenance, f.Confidence*100),
				Type:    f.Provenance,
				Content: fmt.Sprintf("File: %s\nLine: %d\nDetector: %s\nConfidence: %.1f%%\nValue: %s\nDescription: %s",
					f.File, f.Line, f.Detector, f.Confidence*100, f.MatchedValue, f.ReasoningStr),
			},
		}
		suite.Cases = append(suite.Cases, tc)
	}

	suites := JUnitTestSuites{Suites: []JUnitTestSuite{suite}}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suites)
}
