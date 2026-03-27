package tui

import (
	"fmt"

	"github.com/jroimartin/gocui"
)

func setupBanner(g *gocui.Gui, maxX int) error {
	v, err := g.SetView("banner", 0, 0, maxX-sidebarWidth, 2)
	if err != nil {
		if !isNewView(err) {
			return err
		}

		v.Frame = false
		fmt.Fprintf(v, " %s cisco-socks-server", randomArt())
	}

	return nil
}
