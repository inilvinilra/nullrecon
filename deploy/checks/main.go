package main

import (
	"flag"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var forbiddenNames = map[string]bool{
	"utils":   true,
	"helpers": true,
	"common":  true,
	"misc":    true,
	"manager": true,
}

var skippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"bin":          true,
	"vendor":       true,
	"dist":         true,
	"testdata":     true,
}

type violation struct {
	path   string
	reason string
}

func main() {
	root := flag.String("root", ".", "repository root to check")
	flag.Parse()
	violations, err := walk(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checks: %v\n", err)
		os.Exit(2)
	}
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "%s: %s\n", v.path, v.reason)
	}
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "checks: %d violation(s)\n", len(violations))
		os.Exit(1)
	}
	fmt.Println("checks: ok")
}

func walk(root string) ([]violation, error) {
	var out []violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if skippedDirs[name] {
				return filepath.SkipDir
			}
			if path == root {
				return nil
			}
			out = append(out, checkDirName(path, name)...)
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, checkGoFile(path, name)...)
		}
		return nil
	})
	return out, err
}

func checkDirName(path, name string) []violation {
	if strings.HasPrefix(name, ".") {
		return nil
	}
	var out []violation
	if strings.Contains(name, "_") {
		out = append(out, violation{path, "directory name must not contain underscores"})
	}
	if name != strings.ToLower(name) {
		out = append(out, violation{path, "directory name must be lower case"})
	}
	if forbiddenNames[name] {
		out = append(out, violation{path, "forbidden generic directory name"})
	}
	return out
}

func checkGoFile(path, name string) []violation {
	var out []violation
	base := strings.TrimSuffix(name, ".go")
	testFile := strings.HasSuffix(base, "_test")
	checkName := strings.TrimSuffix(base, "_test")
	if strings.Contains(checkName, "_") {
		out = append(out, violation{path, "go file name must not contain underscores"})
	}
	if checkName != strings.ToLower(checkName) {
		out = append(out, violation{path, "go file name must be lower case"})
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return append(out, violation{path, err.Error()})
	}
	formatted, ferr := format.Source(data)
	if ferr != nil {
		out = append(out, violation{path, "not parseable by go/format: " + ferr.Error()})
	} else if string(formatted) != string(data) {
		out = append(out, violation{path, "not gofmt formatted"})
	}
	if !testFile {
		out = append(out, checkComments(path, string(data))...)
	}
	return out
}

func checkComments(path, src string) []violation {
	var out []violation
	line := 1
	i := 0
	n := len(src)
	var inString byte
	for i < n {
		c := src[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if inString != 0 {
			if c == '\\' && inString != '`' {
				i += 2
				continue
			}
			if c == inString {
				inString = 0
			}
			i++
			continue
		}
		switch c {
		case '"', '\'', '`':
			inString = c
			i++
			continue
		case '/':
			if i+1 < n && src[i+1] == '/' {
				end := strings.IndexByte(src[i:], '\n')
				var text string
				if end < 0 {
					text = src[i:]
				} else {
					text = src[i : i+end]
				}
				if !strings.HasPrefix(text, "//go:") {
					out = append(out, violation{fmt.Sprintf("%s:%d", path, line), "comment in production source"})
				}
				if end < 0 {
					i = n
				} else {
					i += end
				}
				continue
			}
			if i+1 < n && src[i+1] == '*' {
				out = append(out, violation{fmt.Sprintf("%s:%d", path, line), "block comment in production source"})
				j := strings.Index(src[i+2:], "*/")
				if j < 0 {
					return out
				}
				segment := src[i : i+2+j+2]
				line += strings.Count(segment, "\n")
				i += 2 + j + 2
				continue
			}
		}
		i++
	}
	return out
}
