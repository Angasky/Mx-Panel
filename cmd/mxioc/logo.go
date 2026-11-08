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

// Seven-row pixel glyphs use double-width blocks on a full-size terminal.
var menuLogo = [5][7]string{
	{"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
	{"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
	{"11111", "00100", "00100", "00100", "00100", "00100", "11111"},
	{"01110", "10001", "10001", "10001", "10001", "10001", "01110"},
	{"01111", "10000", "10000", "10000", "10000", "10000", "01111"},
}

func logoFrame(progress float64, color bool) string {
	return logoFrameSized(progress, color, 2)
}

func logoFrameSized(progress float64, color bool, scale int) string {
	var b strings.Builder
	width := 25*scale + 8
	for row := 0; row < 7; row++ {
		b.WriteString("  ")
		for letter, glyph := range menuLogo {
			if letter > 0 {
				b.WriteString("  ")
			}
			for col, pixel := range glyph[row] {
				x := float64(letter*7+col) / 32
				// Staggered reveal, diagonal white sweep, then a soft final bloom.
				reveal := math.Max(0, math.Min(1, (progress*2.8-x)*3))
				sweep := math.Exp(-math.Pow((x+float64(row)*0.025)-(progress*1.9-0.3), 2) / 0.009)
				bloom := 0.38 * math.Exp(-math.Pow((progress-0.83)/0.09, 2))
				glow := math.Min(1, sweep+bloom)
				red, green, blue := 30+110*x, 210-100*x, 245.0
				if color {
					brightness := 0.16 + 0.84*reveal
					fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm", int((red+(255-red)*glow)*brightness), int((green+(255-green)*glow)*brightness), int((blue+(255-blue)*glow)*brightness))
				}
				cell := " "
				if pixel == '1' {
					cell = "█"
				}
				b.WriteString(strings.Repeat(cell, scale))
			}
		}
		if color {
			b.WriteString("\x1b[0m")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n  ")
	for i := 0; i < width; i++ {
		if color {
			x := float64(i) / float64(width-1)
			fmt.Fprintf(&b, "\x1b[38;2;%d;%d;245m", int(30+110*x), int(210-100*x))
		}
		if float64(i)/float64(width) <= progress || !color {
			b.WriteString("━")
		} else {
			b.WriteString(" ")
		}
	}
	if color {
		b.WriteString("\x1b[0m")
	}
	b.WriteString("\n  M X - P A N E L   /   CONTROL CENTER\n")
	return b.String()
}

func managementLogo() error {
	inputMode, inErr := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	size, outErr := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	interactive := inErr == nil && outErr == nil
	if interactive && (size.Col < 38 || size.Row < 12) {
		_, err := fmt.Fprintln(os.Stdout, "MXIOC")
		return err
	}
	scale := 2
	if interactive && size.Col < 64 {
		scale = 1
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	if !interactive || os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" || noColor || os.Getenv("MX_PANEL_NO_ANIMATION") != "" {
		_, err := fmt.Fprint(os.Stdout, logoFrameSized(1, false, scale))
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Keep canonical input queued for Bash, but avoid echoed keys moving the logo.
	quietMode := *inputMode
	quietMode.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, &quietMode); err != nil {
		_, err = fmt.Fprint(os.Stdout, logoFrameSized(1, false, scale))
		return err
	}
	defer unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, inputMode)
	fmt.Fprint(os.Stdout, "\x1b[?25l")
	defer fmt.Fprint(os.Stdout, "\x1b[0m\x1b[?25h")
	ticker := time.NewTicker(time.Second / 40)
	defer ticker.Stop()
	start := time.Now()
	for frame := 0; ; frame++ {
		currentSize, sizeErr := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
		if sizeErr != nil || currentSize.Col != size.Col || currentSize.Row != size.Row {
			return nil
		}
		progress := math.Min(time.Since(start).Seconds()/2.8, 1)
		prefix := ""
		if frame > 0 {
			prefix = "\x1b[10F"
		}
		if _, err := fmt.Fprint(os.Stdout, prefix+logoFrameSized(progress, true, scale)); err != nil {
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
