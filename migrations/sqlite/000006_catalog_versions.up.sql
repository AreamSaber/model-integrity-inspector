CREATE INDEX providers_active_cursor ON providers (organization_id, id) WHERE deleted_at IS NULL;
CREATE INDEX model_profiles_active_cursor ON model_profiles (organization_id, id) WHERE deleted_at IS NULL;
CREATE INDEX model_profiles_provider_refs ON model_profiles (organization_id, provider_id) WHERE deleted_at IS NULL;
CREATE INDEX targets_provider_refs ON integrity_targets (organization_id, provider_id) WHERE deleted_at IS NULL;
CREATE INDEX targets_profile_refs ON integrity_targets (organization_id, model_profile_id) WHERE deleted_at IS NULL;
