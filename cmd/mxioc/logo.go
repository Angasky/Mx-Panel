package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Each glyph has the same width so the highlight moves without shifting text.
var menuLogo = [5][5]string{
	{"M   M", "MM MM", "M M M", "M   M", "M   M"},
	{"X   X", " X X ", "  X  ", " X X ", "X   X"},
	{"IIIII", "  I  ", "  I  ", "  I  ", "IIIII"},
	{" OOO ", "O   O", "O   O", "O   O", " OOO "},
	{" CCCC", "C    ", "C    ", "C    ", " CCCC"},
}

func logoFrame(progress float64, color bool) string {
	var b strings.Builder
	for row := 0; row < 5; row++ {
		b.WriteString("  ")
		for letter, glyph := range menuLogo {
			if color {
				// A broad, continuous light sweeps M -> X -> I -> O -> C.
				// Neighbouring letters cross-fade instead of blinking on/off.
				distance := (progress*6 - 1) - float64(letter)
				glow := math.Exp(-distance * distance / 0.65)
				fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm", 65+int(170*glow), 110+int(140*glow), 125+int(130*glow))
			}
			b.WriteString(glyph[row])
			b.WriteString("  ")
		}
		if color {
			b.WriteString("\x1b[0m")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func managementLogo() error {
	inputMode, inErr := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	size, outErr := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	interactive := inErr == nil && outErr == nil
	if interactive && (size.Col < 38 || size.Row < 7) {
		_, err := fmt.Fprintln(os.Stdout, "MXIOC")
		return err
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	if !interactive || os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" || noColor || os.Getenv("MX_PANEL_NO_ANIMATION") != "" {
		_, err := fmt.Fprint(os.Stdout, logoFrame(0, false))
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Keep canonical input queued for Bash, but avoid echoed keys moving the logo.
	quietMode := *inputMode
	quietMode.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, &quietMode); err != nil {
		_, err = fmt.Fprint(os.Stdout, logoFrame(0, false))
		return err
	}
	defer unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, inputMode)
	fmt.Fprint(os.Stdout, "\x1b[?25l")
	defer fmt.Fprint(os.Stdout, "\x1b[0m\x1b[?25h")
	ticker := time.NewTicker(time.Second / 30)
	defer ticker.Stop()
	start := time.Now()
	for frame := 0; ; frame++ {
		progress := math.Min(time.Since(start).Seconds()/2, 1)
		prefix := ""
		if frame > 0 {
			prefix = "\x1b[5F"
		}
		if _, err := fmt.Fprint(os.Stdout, prefix+logoFrame(progress, true)); err != nil {
			return err
		}
		if progress >= 1 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
