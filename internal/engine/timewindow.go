package engine

import (
	"log/slog"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
	"github.com/robfig/cron/v3"
)

// isInTimeWindow checks whether the current time falls within the rule's
// active cron window. The cron expression defines when the rule is active.
// We check if the most recent scheduled time is within the last minute.
func isInTimeWindow(tw *policy.TimeWindow) bool {
	if tw == nil || tw.ActiveCron == "" {
		return true // no time window = always active
	}

	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(tw.ActiveCron)
	if err != nil {
		slog.Warn("invalid cron expression in time_window", "cron", tw.ActiveCron, "error", err)
		return false
	}

	now := time.Now()
	if tw.Timezone != "" {
		loc, err := time.LoadLocation(tw.Timezone)
		if err != nil {
			slog.Warn("invalid timezone in time_window", "timezone", tw.Timezone, "error", err)
			return false
		}
		now = now.In(loc)
	}

	// Check if now matches the cron schedule by seeing if the next scheduled
	// time from one minute ago is within the current minute.
	oneMinuteAgo := now.Add(-1 * time.Minute)
	nextRun := sched.Next(oneMinuteAgo)

	// The rule is active if the next scheduled time from a minute ago
	// is at or before now (meaning now is a scheduled minute).
	return !nextRun.After(now)
}
