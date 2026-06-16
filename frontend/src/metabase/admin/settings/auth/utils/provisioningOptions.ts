import { t } from "ttag";

export function oidcProvisioningOptions(label: string) {
  const enabledLabel = t`Enabled: When a user logs in via ${label}, automatically create an account for them if they don't have one, or reactivate their existing account.`;
  const disabledLabel = t`Disabled: Only users with active Metabase accounts can log in using ${label}.`;

  return [
    { value: "true", label: enabledLabel },
    { value: "false", label: disabledLabel },
  ];
}
