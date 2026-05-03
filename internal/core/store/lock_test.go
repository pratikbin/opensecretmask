package store

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExclusive_BlocksThenAllows(t *testing.T) {
	dir := t.TempDir()

	holder, err := OpenLock(dir)
	require.NoError(t, err)
	contender, err := OpenLock(dir)
	require.NoError(t, err)

	release := make(chan struct{})
	held := make(chan struct{})
	holderDone := make(chan error, 1)

	go func() {
		holderDone <- holder.WithExclusive(2*time.Second, func() error {
			close(held)
			<-release
			return nil
		})
	}()

	<-held

	err = contender.WithExclusive(50*time.Millisecond, func() error { return nil })
	require.Error(t, err)

	close(release)
	require.NoError(t, <-holderDone)

	require.NoError(t, contender.WithExclusive(2*time.Second, func() error { return nil }))
}

func TestSharedShared_Coexist(t *testing.T) {
	dir := t.TempDir()

	a, err := OpenLock(dir)
	require.NoError(t, err)
	b, err := OpenLock(dir)
	require.NoError(t, err)

	var wg sync.WaitGroup
	bothIn := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)

	run := func(l *Lock) {
		defer wg.Done()
		errs <- l.WithShared(100*time.Millisecond, func() error {
			bothIn <- struct{}{}
			<-release
			return nil
		})
	}

	wg.Add(2)
	go run(a)
	go run(b)

	<-bothIn
	<-bothIn
	close(release)
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}

func TestShared_BlocksExclusive(t *testing.T) {
	dir := t.TempDir()

	holder, err := OpenLock(dir)
	require.NoError(t, err)
	contender, err := OpenLock(dir)
	require.NoError(t, err)

	release := make(chan struct{})
	held := make(chan struct{})
	holderDone := make(chan error, 1)

	go func() {
		holderDone <- holder.WithShared(2*time.Second, func() error {
			close(held)
			<-release
			return nil
		})
	}()

	<-held

	err = contender.WithExclusive(50*time.Millisecond, func() error { return nil })
	require.Error(t, err)

	close(release)
	require.NoError(t, <-holderDone)
}
