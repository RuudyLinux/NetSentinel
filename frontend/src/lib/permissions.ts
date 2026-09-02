/** Mirrors backend/app/security/permissions.py's Permission enum — keep in sync. */
export const Permission = {
  DEVICE_READ: "DEVICE_READ",
  DEVICE_WRITE: "DEVICE_WRITE",
  CONFIG_UPLOAD: "CONFIG_UPLOAD",
  AUDIT_RUN: "AUDIT_RUN",
  AUDIT_READ: "AUDIT_READ",
  FINDING_READ: "FINDING_READ",
  FINDING_TRIAGE: "FINDING_TRIAGE",
  REPORT_GENERATE: "REPORT_GENERATE",
  REPORT_READ: "REPORT_READ",
  USER_ADMIN: "USER_ADMIN",
  MAPPING_SUGGEST: "MAPPING_SUGGEST",
  MAPPING_APPROVE: "MAPPING_APPROVE",
} as const;

export type Permission = (typeof Permission)[keyof typeof Permission];
