// Package policy - file/ConfigMap watcher for policy hot-reload.
package policy

import (
	"log/slog"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// Watcher monitors a policy file for changes and triggers reload.
type Watcher struct {
	path     string
	onChange func()
	watcher  *fsnotify.Watcher
	done     chan struct{}
	once     sync.Once
}

// NewWatcher creates a file watcher. onChange is called when the file changes.
// Works with regular files and Kubernetes ConfigMap mounts (symlink-based updates).
func NewWatcher(path string, onChange func()) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Watch the directory containing the file, not just the file itself.
	// This is necessary for Kubernetes ConfigMap mounts, which replace
	// the symlink target (..data -> ..timestamp) rather than modifying
	// the file in place.
	if err := fsw.Add(path); err != nil {
		// Try the directory
		fsw.Close()
		fsw, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		// Extract directory
		dir := path
		for i := len(dir) - 1; i >= 0; i-- {
			if dir[i] == '/' {
				dir = dir[:i]
				break
			}
		}
		if err := fsw.Add(dir); err != nil {
			fsw.Close()
			return nil, err
		}
	}

	w := &Watcher{
		path:     path,
		onChange: onChange,
		watcher:  fsw,
		done:     make(chan struct{}),
	}

	go w.run()
	return w, nil
}

func (w *Watcher) run() {
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			// ConfigMap mounts trigger CREATE events on the symlink.
			// Regular file edits trigger WRITE events.
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				slog.Info("policy file changed, reloading", "path", w.path, "event", event.Op)
				w.onChange()
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("file watcher error", "error", err)
		case <-w.done:
			return
		}
	}
}

// Close stops the watcher.
func (w *Watcher) Close() {
	w.once.Do(func() {
		close(w.done)
		w.watcher.Close()
	})
}
