package flags

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kr/text"
)

func Usage(txt string, flags *flag.FlagSet) string {
	u := &Usager{
		Usage: txt,
		Flags: flags,
	}
	return u.String()
}

type Usager struct {
	Usage string
	Flags *flag.FlagSet
}

func (u *Usager) String() string {
	usage := new(bytes.Buffer)
	usage.WriteString(strings.TrimSpace(u.Usage))
	usage.WriteString("\n")
	usage.WriteString("\n")
	if u.Flags != nil {
		printTitle(usage, "Command Options")
		u.Flags.VisitAll(func(f *flag.Flag) {
			printFlag(usage, f)
		})
	}
	return strings.TrimRight(usage.String(), "\n")
}

// printTitle prints a consistently-formatted title to the given writer.
func printTitle(w io.Writer, s string) {
	fmt.Fprintf(w, "%s\n\n", s)
}

// printFlag prints a single flag to the given writer.
func printFlag(w io.Writer, f *flag.Flag) {
	example, _ := flag.UnquoteUsage(f)
	if example != "" {
		fmt.Fprintf(w, "  -%s=<%s>\n", f.Name, example)
	} else {
		fmt.Fprintf(w, "  -%s\n", f.Name)
	}

	indented := wrapAtLength(f.Usage, 5)
	fmt.Fprintf(w, "%s\n\n", indented)
}

// maxLineLength is the maximum width of any line.
const maxLineLength int = 72

// wrapAtLength wraps the given text at the maxLineLength, taking into account
// any provided left padding.
func wrapAtLength(s string, pad int) string {
	wrapped := text.Wrap(s, maxLineLength-pad)
	lines := strings.Split(wrapped, "\n")
	for i, line := range lines {
		lines[i] = strings.Repeat(" ", pad) + line
	}
	return strings.Join(lines, "\n")
}
