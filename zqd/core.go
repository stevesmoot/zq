package zqd

import (
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/brimsec/zq/zqd/zeek"
	"go.uber.org/zap"
)

type Config struct {
	Root string
	// ZeekLauncher is the interface for launching zeek processes.
	ZeekLauncher zeek.Launcher
	// SortLimit specifies the limit of logs in posted pcap to sort. Its
	// existence is only as a hook for testing.  Eventually zqd will sort an
	// unlimited amount of logs and this can be taken out.
	SortLimit int
	Logger    *zap.Logger
}

type VersionMessage struct {
	Zqd string `json:"boomd"` //XXX boomd -> zqd
	Zq  string `json:"zq"`
}

// This struct filled in by main from linker setting version strings.
var Version VersionMessage

type Core struct {
	Root         string
	ZeekLauncher zeek.Launcher
	// SortLimit specifies the limit of logs in posted pcap to sort. Its
	// existence is only as a hook for testing.  Eventually zqd will sort an
	// unlimited amount of logs and this can be taken out.
	SortLimit int
	taskCount int64
	logger    *zap.Logger

	ingestLock sync.Mutex
	ingests    map[string]*ingestWaitState
}

type ingestWaitState struct {
	deletePending bool
	wg            sync.WaitGroup
	cancelChan    chan struct{}
}

func NewCore(conf Config) *Core {
	logger := conf.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Core{
		Root:         conf.Root,
		ZeekLauncher: conf.ZeekLauncher,
		SortLimit:    conf.SortLimit,
		logger:       logger,
		ingests:      make(map[string]*ingestWaitState),
	}
}

func (c *Core) HasZeek() bool {
	return c.ZeekLauncher != nil
}

func (c *Core) requestLogger(r *http.Request) *zap.Logger {
	return c.logger.With(zap.String("request_id", getRequestID(r.Context())))
}

func (c *Core) getTaskID() int64 {
	return atomic.AddInt64(&c.taskCount, 1)
}

func (c *Core) startIngest(space string) (cancelChan chan struct{}, ok bool) {
	c.logger.Info("startIngest", zap.String("space", space))
	c.ingestLock.Lock()
	defer c.ingestLock.Unlock()

	iws, ok := c.ingests[space]
	if !ok {
		iws = &ingestWaitState{
			cancelChan: make(chan struct{}, 0),
		}
		c.ingests[space] = iws
	}
	if iws.deletePending {
		return nil, false
	}
	iws.wg.Add(1)
	return iws.cancelChan, true
}

func (c *Core) finishIngest(space string) {
	c.logger.Info("finishIngest", zap.String("space", space))
	c.ingestLock.Lock()
	defer c.ingestLock.Unlock()
	iws := c.ingests[space]
	iws.wg.Done()
}

func (c *Core) startSpaceDelete(space string) {
	c.logger.Info("startSpaceDelete", zap.String("space", space))
	c.ingestLock.Lock()
	iws, ok := c.ingests[space]
	if !ok {
		c.ingestLock.Unlock()
		return
	}
	iws.deletePending = true
	close(iws.cancelChan)
	c.ingestLock.Unlock()
	iws.wg.Wait()
}

func (c *Core) finishSpaceDelete(space string) {
	c.logger.Info("finishSpaceDelete", zap.String("space", space))
	c.ingestLock.Lock()
	defer c.ingestLock.Unlock()
	delete(c.ingests, space)
}
