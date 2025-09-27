package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gomal/pkg/pe"
)

// No color constants for better Windows compatibility

func printTitle(title string) {
	width := 80
	padding := (width - len(title) - 4) / 2
	line := strings.Repeat("=", width)
	fmt.Printf("\n%s\n%s %s %s\n%s\n", line, strings.Repeat(" ", padding), title, strings.Repeat(" ", padding), line)
}

func printWarning(msg string) {
	fmt.Printf("[!] WARNING: %s\n", msg)
}

func printError(msg string) {
	fmt.Printf("[!] ALERT: %s\n", msg)
}

func printInfo(msg string) {
	fmt.Printf("[*] %s\n", msg)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: peanalyze <path-to-pefile>")
		return
	}

	filePath := os.Args[1]
	analysis, err := pe.OpenAndAnalyzeEntropy(filePath)
	if err != nil {
		printError(fmt.Sprintf("Error analyzing file: %v", err))
		return
	}

	// Print file information
	fileName := filepath.Base(filePath)
	printTitle(fmt.Sprintf("PE Analysis: %s", fileName))

	// Print section analysis
	printTitle("Section Analysis")
	fmt.Printf("%-12s | %-12s | %-12s | %-8s | %-7s | %s\n",
		"Name", "Virt Addr", "Virt Size", "Size", "Entropy", "Characteristics")
	fmt.Println(strings.Repeat("-", 90))

	for _, sec := range analysis.Sections {
		// Print basic section info
		fmt.Printf("%-12s | 0x%-10X | 0x%-10X | %-8d | %-7.2f | %s\n",
			sec.Name,
			sec.VirtualAddress,
			sec.VirtualSize,
			sec.Size,
			sec.Entropy,
			strings.Join(sec.Characteristics, ", "))

		// Print section warnings
		if sec.HighEntropy {
			fmt.Printf("   └─ High entropy detected (%.2f bits/byte)\n",
				sec.Entropy)
		}
	}

	// Print packer detection results
	if len(analysis.PackerSigns) > 0 {
		printTitle("Packer Detection")
		for _, packer := range analysis.PackerSigns {
			printError(fmt.Sprintf("Detected %s packer", packer.Name))
			printInfo(fmt.Sprintf("Section: %s", packer.MatchedOn))
			printInfo(fmt.Sprintf("Description: %s", packer.Description))
			fmt.Println()
		}
	}

	// Print overall analysis
	printTitle("Overall Analysis")
	fmt.Printf("File entropy: %.2f bits/byte\n", analysis.WholeEntropy)

	if analysis.IsHighEntropy {
		printWarning(fmt.Sprintf("High file entropy detected (%.2f bits/byte)", analysis.WholeEntropy))
		printInfo("This may indicate:")
		fmt.Println("   - Packing")
		fmt.Println("   - Encryption")
		fmt.Println("   - Compression")
	} else {
		printInfo("No abnormal entropy levels detected in the file")
	}
}
