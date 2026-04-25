package state

import (
	"fmt"
	"log/slog"
	"reflect"
	"runtime"
	"time"
)

// Dispatch Dispatches the function to run on the main thread without waiting for it to complete
func (e *Env) Dispatch(fun func(*State) error) {
	defer func() {
		if r := recover(); r != nil {
			e.Cancel(fmt.Errorf("dispatch panic: %v", r))
		}
	}()
	if e.DispatchChannel == nil {
		e.log().Error("dispatch channel is nil, discarded function", "fun", funcName(fun))
		return
	}
	var done <-chan struct{}
	if e.Context != nil {
		done = e.Context.Done()
	}
	select {
	case e.DispatchChannel <- fun:
	case <-done:
		e.log().Debug("dispatch skipped after shutdown", "fun", funcName(fun), "err", e.Context.Err())
	}
}

func (e *Env) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func funcName(fun func(*State) error) string {
	if fun == nil {
		return "<nil>"
	}
	return runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
}

func (e *Env) ScheduleTask(fun func(*State) error, delay time.Duration) {
	time.AfterFunc(delay, func() {
		e.Dispatch(fun)
	})
}

func (e *Env) repeatedTask(fun func(*State) error, delay time.Duration) {
	// run immediately
	e.Dispatch(fun)
	ticker := time.NewTicker(delay)
	for e.Context.Err() == nil {
		select {
		case <-e.Context.Done():
			return
		case <-ticker.C:
			e.Dispatch(fun)
		}
	}
}

func (e *Env) RepeatTask(fun func(*State) error, delay time.Duration) {
	go e.repeatedTask(fun, delay)
}
