package cert

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNotify(t *testing.T) {
	t.Parallel()

	// Source is just randomly generated
	source := testGenSource()
	source.Expiry = 5 * time.Second
	source.ExpiryWithin = 2 * time.Second

	// Create notifier
	ch := make(chan Bundle)
	n := &Notify{Ch: ch, Source: source}
	defer n.Stop()
	go n.Start(context.Background())

	// We should receive an update almost immediately
	select {
	case <-time.After(250 * time.Millisecond):
		t.Fatal("should've received initial bundle")
	case b := <-ch:
		testBundleVerify(t, &b)
	}

	// We should not receive an update for at least one second
	select {
	case <-time.After(750 * time.Millisecond):
	case <-ch:
		t.Fatal("should not receive update")
	}

	b := <-ch
	testBundleVerify(t, &b)
}

// TestNotifyRace attempts to create a race. If it exists, it
// will be picked up by the race detector, causing tests to fail.
func TestNotifyRace(t *testing.T) {
	// Use an arbitrary amount of parallelism to try to cause a race.
	numParallel := 100

	// Use one background context for everything since that could happen
	// IRL.
	ctx := context.Background()

	// The start channel will be used to fire everything at once.
	start := make(chan interface{})

	// The done channel will be used to wait for everything to finish,
	// giving races a chance to be detected.
	done := make(chan interface{})

	// Set up a realistic Notify object, modelling off of its use in
	// command.go.
	certCh := make(chan Bundle)
	var certSource Source = &GenSource{
		Name:  "Agent Inject",
		Hosts: []string{"some", "hosts"},
	}
	n := &Notify{Ch: certCh, Source: certSource}
	for i := 0; i < numParallel; i++ {
		go func() {
			<-start
			fmt.Println("starting Start")
			n.Start(ctx)
			fmt.Println("finishing Start")
			done <- true
		}()
		go func() {
			<-start
			fmt.Println("starting Stop")
			n.Stop()
			fmt.Println("finishing Stop")
			done <- true
		}()
	}
	close(start)

	// For each numParallel, we start 2 goroutines. Now we need
	// to wait for them all to finish. Let's give up to 10 seconds.
	timer := time.NewTimer(10 * time.Second)
	for i := 0; i < (2 * numParallel); i++ {
		select {
		case <-done:
			fmt.Printf("%d are done\n", i)
			continue
		case <- timer.C:
			t.Fatal("test didn't finish in 10 seconds")
		}
	}

	// If we arrived here without a test failure or race, we're
	// good to go!
}
