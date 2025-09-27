package pe

// PackerSignature represents a known packer signature
type PackerSignature struct {
	Name        string
	SectionName string // regex pattern for section name
	Description string
}

// Known packer signatures
var knownPackers = []PackerSignature{
	{
		Name:        "UPX",
		SectionName: `UPX[0-9]`,
		Description: "Ultimate Packer for eXecutables",
	},
	{
		Name:        "ASPack",
		SectionName: `\.aspack`,
		Description: "ASPack Packer",
	},
	{
		Name:        "PECompact",
		SectionName: `PEC2`,
		Description: "PECompact Packer",
	},
	{
		Name:        "FSG",
		SectionName: `FSG`,
		Description: "Fast Small Good Packer",
	},
	{
		Name:        "PEtite",
		SectionName: `PETite`,
		Description: "PEtite Packer",
	},
	{
		Name:        "MEW",
		SectionName: `MEW`,
		Description: "MEW Packer",
	},
	{
		Name:        "MPRESS",
		SectionName: `\.MPRESS[1-9]`,
		Description: "MPRESS Packer",
	},
}
