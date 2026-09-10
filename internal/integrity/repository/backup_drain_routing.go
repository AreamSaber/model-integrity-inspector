package repository

// JobType exposes only a closed routing discriminator from the original owned
// source. It is not a Job DTO, a current-state observation, or authorization to
// Apply. Every operation must still revalidate the private maintenance binding.
// In particular, terminal_required must not route by trying an execution Apply
// and treating an invalid/unsupported execution source as another domain.
func (s *BackupDrainSource) JobType() JobType {
	if s == nil {
		return ""
	}
	switch kind := JobType(s.job.Type); kind {
	case JobRunPlan, JobSampleExecute, JobRunAnalyze, JobReportGenerate, JobTargetPrecheck, JobRetentionDelete, JobNotificationSend:
		return kind
	default:
		return ""
	}
}
