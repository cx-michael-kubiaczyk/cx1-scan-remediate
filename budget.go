package main

import (
	"math"
	"time"
)

// budget is the overall time allowance for the AI Triage and AI Remediation phases of a run.
// A zero end means no limit. Publishing a pull request is never cut short by the budget: a
// remediation that has already been generated (and paid for) is always published.
type budget struct {
	end time.Time
}

// newBudget starts a budget of d from now; d <= 0 means no limit.
func newBudget(d time.Duration) budget {
	if d <= 0 {
		return budget{}
	}
	return budget{end: time.Now().Add(d)}
}

func (b budget) unlimited() bool { return b.end.IsZero() }

func (b budget) remaining() time.Duration {
	if b.unlimited() {
		return time.Duration(math.MaxInt64)
	}
	return time.Until(b.end)
}

func (b budget) expired() bool { return !b.unlimited() && b.remaining() <= 0 }

// pollTimeouts returns the delay and maximum, in seconds, to pass to a library polling call:
// the library's own maximum, or the time remaining if that is smaller. The result is at least
// one second, so once the budget is spent a poll is still a quick check whether the job has
// already finished. A library maximum of 0 means "no limit" and is replaced by the remaining
// time when a budget is set. The delay is capped to the maximum so the library's retry sleep
// cannot overshoot the budget by a whole delay interval.
func (b budget) pollTimeouts(libDelay, libMax int) (delay, max int) {
	if b.unlimited() {
		return libDelay, libMax
	}
	rem := int(math.Ceil(b.remaining().Seconds()))
	if rem < 1 {
		rem = 1
	}
	max = libMax
	if max == 0 || rem < max {
		max = rem
	}
	delay = libDelay
	if delay > max {
		delay = max
	}
	if delay < 1 {
		delay = 1
	}
	return delay, max
}
