package tui

import (
	"fmt"

	"github.com/jroimartin/gocui"
)

func setupHelp(g *gocui.Gui, maxX int) error {
	v, err := g.SetView("help", maxX-sidebarWidth+1, 2, maxX-1, 4)
	if err != nil {
		if !isNewView(err) {
			return err
		}

		v.Frame = false
		fmt.Fprint(v, colorize("  Ctrl+C", 14), colorize(" exit", 7))
	}

	return nil
}
