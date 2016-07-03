package fastd

import (
	"log"
	"time"
)

const (
	peerCheckInterval = 15 * time.Second
)

func (srv *Server) startTimeouter() {
	srv.wg.Add(1)

	go func() {
		for {
			select {
			case <-srv.timeoutStop:
				srv.wg.Done()
				return
			case <-srv.timeoutTicker.C:
				srv.timeoutPeers()
			}
		}
	}()
}

func (srv *Server) stopTimeouter() {
	srv.timeoutTicker.Stop()
	srv.timeoutStop <- struct{}{}
}

// Removes timed out peers
func (srv *Server) timeoutPeers() {
	srv.peersMtx.Lock()
	defer srv.peersMtx.Unlock()

	now := time.Now()

	for _, peer := range srv.peers {
		if peer.hasTimeout(now, srv.config.Timeout) {
			log.Println(peer.Ifname, "timed out")
			srv.removePeerLocked(peer)
		}
	}
}

// Returns true if the counter has been updated
func (peer *Peer) updateCounter(now time.Time) bool {
	stats, err := GetStats(peer.Ifname)
	if err != nil {
		log.Printf("Unable to get stats for %s: %s", peer.Ifname, err)
		return false
	}

	// packet counter changed?
	if peer.ipackets != stats.ipackets {
		peer.ipackets = stats.ipackets
		peer.lastSeen = now
		return true
	}

	return false
}

// Returns whether the peer is timed out
func (peer *Peer) hasTimeout(now time.Time, peerTimeout time.Duration) bool {
	if peer.Ifname != "" && peer.updateCounter(now) {
		return false
	}

	return peer.lastSeen.Add(peerTimeout).Before(now)
}
