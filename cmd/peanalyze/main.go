package main

import (
	"fmt"
	"os"

	"gomal/pkg/pe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: peanalyze <path-to-pefile>")
		return
	}

	filePath := os.Args[1]
	analysis, err := pe.OpenAndAnalyze(filePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Print section analysis
	for _, sec := range analysis.Sections {
		fmt.Printf("Section %-8s | Size: %-7d | Entropy: %.2f bits/byte | High Entropy: %v\n",
			sec.Name, sec.Size, sec.Entropy, sec.HighEntropy)
	}

	// Print whole file analysis
	fmt.Printf("\nWhole file entropy: %.2f bits/byte\n", analysis.WholeEntropy)
	if analysis.IsHighEntropy {
		fmt.Printf("Warning: The whole file has high entropy (%.2f bits/byte), which may indicate packing or encryption.\n", analysis.WholeEntropy)
	}
}
