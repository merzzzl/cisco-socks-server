package tui

import (
	"fmt"

	"github.com/jroimartin/gocui"
)

func setupHelp(g *gocui.Gui, maxX, maxY int) error {
	v, err := g.SetView("help", maxX-sidebarWidth+1, maxY-2, maxX-1, maxY)
	if err != nil {
		if !isNewView(err) {
			return err
		}

		v.Frame = false
		fmt.Fprint(v, colorize(" Ctrl+C", 14), colorize(" exit", 7))
	}

	return nil
}
