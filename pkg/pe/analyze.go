package pe

import (
	"debug/pe"
	"fmt"
	"os"

	"gomal/pkg/entropy"
)

// FileAnalysis contains the analysis results of a PE file
type FileAnalysis struct {
	Sections      []SectionAnalysis
	WholeEntropy  float64
	IsHighEntropy bool
}

// SectionAnalysis contains analysis information for a PE section
type SectionAnalysis struct {
	Name        string
	Size        int
	Entropy     float64
	HighEntropy bool
}

// OpenAndAnalyze opens a PE file and performs entropy analysis
func OpenAndAnalyze(filePath string) (*FileAnalysis, error) {
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
			Name:        sec.Name,
			Size:        len(data),
			Entropy:     e,
			HighEntropy: e > 7.2,
		})
	}

	// Overall file entropy
	if allData, err := os.ReadFile(filePath); err == nil {
		analysis.WholeEntropy = entropy.Calculate(allData)
		analysis.IsHighEntropy = analysis.WholeEntropy > 7.2
	}

	return analysis, nil
}
