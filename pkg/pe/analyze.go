package pe

import (
	"debug/pe"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gomal/pkg/entropy"
)

// FileAnalysis contains the analysis results of a PE file
type FileAnalysis struct {
	Sections      []SectionAnalysis
	WholeEntropy  float64
	IsHighEntropy bool
	PackerSigns   []PackerMatch
}

// SectionAnalysis contains analysis information for a PE section
type SectionAnalysis struct {
	Name            string
	Size            int
	Entropy         float64
	HighEntropy     bool
	Characteristics []string
	VirtualSize     uint32
	VirtualAddress  uint32
	Raw             []byte
}

// PackerMatch represents a matched packer signature
type PackerMatch struct {
	Name        string
	Description string
	MatchedOn   string
}

// getSectionCharacteristics returns human-readable section characteristics
func getSectionCharacteristics(characteristics uint32) []string {
	var chars []string

	// Memory permissions
	if characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
		chars = append(chars, "Executable")
	}
	if characteristics&pe.IMAGE_SCN_MEM_READ != 0 {
		chars = append(chars, "Readable")
	}
	if characteristics&pe.IMAGE_SCN_MEM_WRITE != 0 {
		chars = append(chars, "Writable")
	}

	// Content type
	if characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
		chars = append(chars, "Contains Code")
	}
	if characteristics&pe.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
		chars = append(chars, "Contains Data")
	}
	if characteristics&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
		chars = append(chars, "Uninitialized Data")
	}
	if characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
		chars = append(chars, "Discardable")
	}

	return chars
}

// OpenAndAnalyze opens a PE file and performs entropy analysis
func OpenAndAnalyzeEntropy(filePath string) (*FileAnalysis, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open PE file: %v", err)
	}
	defer f.Close()

	analysis := &FileAnalysis{}

	// Analyze sections
	for _, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil {
			continue
		}
		e := entropy.Calculate(data)
		analysis.Sections = append(analysis.Sections, SectionAnalysis{
			Name:            strings.TrimRight(sec.Name, "\x00"),
			Size:            len(data),
			Entropy:         e,
			HighEntropy:     e > 7.2,
			Characteristics: getSectionCharacteristics(sec.Characteristics),
			VirtualSize:     sec.VirtualSize,
			VirtualAddress:  sec.VirtualAddress,
			Raw:             data,
		})
	}

	// Detect potential packers
	analysis.PackerSigns = detectPackers(analysis.Sections)

	// Overall file entropy
	if allData, err := os.ReadFile(filePath); err == nil {
		analysis.WholeEntropy = entropy.Calculate(allData)
		analysis.IsHighEntropy = analysis.WholeEntropy > 7.2
	}

	return analysis, nil
}

// detectPackers checks for known packer signatures in section names and content
func detectPackers(sections []SectionAnalysis) []PackerMatch {
	var matches []PackerMatch

	// Check section names for packer signatures
	for _, packer := range knownPackers {
		regex := regexp.MustCompile(packer.SectionName)
		for _, section := range sections {
			if regex.MatchString(strings.TrimSpace(section.Name)) {
				matches = append(matches, PackerMatch{
					Name:        packer.Name,
					Description: packer.Description,
					MatchedOn:   section.Name,
				})
				break
			}
		}
	}

	return matches
}
