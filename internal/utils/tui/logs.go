package tui

import (
	"fmt"

	"github.com/jroimartin/gocui"
)

func setupLogs(g *gocui.Gui, logs <-chan string, done <-chan struct{}, maxX, maxY int) error {
	v, err := g.SetView("logs", 0, 3, maxX-sidebarWidth, maxY-1)
	if err != nil {
		if !isNewView(err) {
			return err
		}

		v.Title = " Logs "
		v.Wrap = true
		v.Autoscroll = true

		go func() {
			for {
				select {
				case <-done:
					return
				case msg := <-logs:
					g.Update(func(*gocui.Gui) error {
						fmt.Fprint(v, msg)

						return nil
					})
				}
			}
		}()
	}

	return nil
}
