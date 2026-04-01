package analysis

import (
	"fmt"
	"io"
	"os"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

type ParsedFile struct {
	Path string
	AST  *ast.Program
}

func ParseFile(filePath string) (*ParsedFile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	src, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	program, err := parser.ParseFile(nil, filePath, string(src), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	return &ParsedFile{
		Path: filePath,
		AST:  program,
	}, nil
}
