package approval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// TerminalHandler prompts for approval via /dev/tty.
type TerminalHandler struct {
	showArgs bool
}

func NewTerminalHandler(showArgs bool) *TerminalHandler {
	return &TerminalHandler{showArgs: showArgs}
}

func (h *TerminalHandler) RequestApproval(ctx context.Context, req Request) (Result, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Result{}, ErrNoTTY
	}
	defer tty.Close()

	start := time.Now()

	// Display prompt
	fmt.Fprintf(tty, "\n\033[1;33m APPROVAL REQUIRED\033[0m\n")
	fmt.Fprintf(tty, " Tool:  %s\n", req.ToolName)
	if h.showArgs && len(req.Arguments) > 0 {
		fmt.Fprintf(tty, " Args:  %s\n", truncateArgs(req.Arguments, 200))
	}
	fmt.Fprintf(tty, " Rule:  %s\n", req.RuleName)
	if req.Message != "" {
		fmt.Fprintf(tty, " Note:  %s\n", req.Message)
	}
	fmt.Fprintf(tty, "\n [a]pprove  [r]eject  [v]iew full args  > ")

	reader := bufio.NewReader(tty)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(tty, "\n Timed out — rejecting.\n\n")
			return Result{
				Approved:  false,
				Reason:    "timeout",
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return Result{
				Approved:  false,
				Reason:    "read error",
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		}

		input := strings.TrimSpace(strings.ToLower(line))
		switch input {
		case "a", "approve", "y", "yes":
			fmt.Fprintf(tty, " \033[32mApproved.\033[0m\n\n")
			return Result{
				Approved:  true,
				Approver:  "terminal",
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		case "r", "reject", "n", "no":
			fmt.Fprintf(tty, " \033[31mRejected.\033[0m\n\n")
			return Result{
				Approved:  false,
				Approver:  "terminal",
				Reason:    "rejected by operator",
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		case "v", "view":
			fmt.Fprintf(tty, "\n Full arguments:\n")
			var pretty bytes.Buffer
			if json.Indent(&pretty, req.Arguments, " ", "  ") == nil {
				fmt.Fprintf(tty, " %s\n", pretty.String())
			} else {
				fmt.Fprintf(tty, " %s\n", string(req.Arguments))
			}
			fmt.Fprintf(tty, "\n [a]pprove  [r]eject  > ")
		default:
			fmt.Fprintf(tty, " Invalid input. [a]pprove  [r]eject  [v]iew  > ")
		}
	}
}

func truncateArgs(args json.RawMessage, maxLen int) string {
	s := string(args)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
