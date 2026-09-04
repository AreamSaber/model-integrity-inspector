package worker

import (
	"context"
	"log/slog"
)

func Run(ctx context.Context, logger *slog.Logger) error {
	logger.Info("worker scaffold ready", "queue", "database", "implementation", "M1-06")
	<-ctx.Done()
	return nil
}
