package tui

import (
	"fmt"
	"time"

	"github.com/jroimartin/gocui"
)

func setupUptime(g *gocui.Gui, done <-chan struct{}, maxX int) error {
	v, err := g.SetView("uptime", maxX-sidebarWidth+1, 0, maxX-1, 2)
	if err != nil {
		if !isNewView(err) {
			return err
		}

		v.Frame = false
		start := time.Now()

		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					g.Update(func(*gocui.Gui) error {
						v.Clear()

						d := time.Since(start)
						h := int(d.Hours())
						m := int(d.Minutes()) % 60
						s := int(d.Seconds()) % 60

						w := sidebarWidth - 3
						line1 := fmt.Sprintf("⏱ %02d:%02d:%02d", h, m, s)

						fmt.Fprintf(v, "%*s", w, line1)

						return nil
					})
				}
			}
		}()
	}

	return nil
}
