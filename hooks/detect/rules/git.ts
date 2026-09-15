import { rule, type Rule } from '../rule'

/**
 * GitLab token variants beyond the personal access token in `builtinRules`.
 * GitHub is already covered there by `gh[pousr]_` and `github_pat_`.
 */
export const gitRules: Rule[] = [
  rule('GitLab Pipeline Trigger Token', 'critical', /glptt-[0-9a-f]{40}/g),
  rule('GitLab Runner Registration Token', 'critical', /GR1348941[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab Feed Token', 'high', /glft-[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab Incoming Mail Token', 'high', /glimt-[0-9a-zA-Z_\-]{25}/g),
  rule('GitLab Kubernetes Agent Token', 'critical', /glagent-[0-9a-zA-Z_\-]{50}/g),
  rule('GitLab CI/CD Job Token', 'critical', /glcbt-[0-9a-zA-Z_\-]{20,}/g),
  rule('GitLab Deploy Token', 'critical', /gldt-[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab SCIM Token', 'critical', /glsoat-[0-9a-zA-Z_\-]{20,}/g),
  rule('GitLab OIDC Application Secret', 'critical', /gloas-[0-9a-zA-Z_\-]{64}/g),
  rule('GitLab Runner Authentication Token', 'critical', /glrt-[0-9a-zA-Z_\-]{20}/g),
  // Group 1 keeps the cookie name out of the mask.
  rule('GitLab Session Cookie', 'high', /_gitlab_session=([0-9a-z]{32})/g, 1),
]
