package gateway

import (
	"sync"
	"testing"
)

// Regression: Allow read l.ratePerMinute before taking l.mu while LowerRate
// writes it under l.mu — an unsynchronized read on the hot per-request path
// racing the enterprise policy reload callback. Run with -race.
func TestSubjectRateLimiter_AllowConcurrentLowerRate(t *testing.T) {
	t.Parallel()
	l := NewSubjectRateLimiter(600, 100, 0, 0)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = l.Allow("tenant|subject|profile")
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		l.LowerRate(300, 0)
		l.LowerRate(600, 0)
	}
	close(stop)
	wg.Wait()
}
