package tui

import (
	"fmt"
	"time"

	"github.com/jroimartin/gocui"

	"github.com/merzzzl/cisco-socks-server/internal/service"
)

func setupStatus(g *gocui.Gui, svc *service.Service, done <-chan struct{}, maxX, maxY int) error {
	v, err := g.SetView("status", maxX-sidebarWidth+1, 3, maxX-1, maxY-1)
	if err != nil {
		if !isNewView(err) {
			return err
		}

		v.Title = " Status "

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

						state := svc.GetState()

						fmt.Fprintf(v, " VPN    %s\n", indicator(state.CiscoConnected))
						fmt.Fprintf(v, " Filter %s\n", indicator(state.PFDisabled))
						fmt.Fprintf(v, " Proxy  %s\n", indicator(state.ProxyStarted))

						return nil
					})
				}
			}
		}()
	}

	return nil
}

func indicator(ok bool) string {
	if ok {
		return colorize("● OK", 10)
	}

	return colorize("○ --", 9)
}
