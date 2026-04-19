package engine

// MaxConcurrentTasks returns the number of scan tasks that can safely execute
// in parallel within a single agent process.
//
// The engine still binds parts of the pipeline onto legacy package globals, so
// only one task can run safely at a time until that migration is complete.
func MaxConcurrentTasks() int {
	return 1
}
