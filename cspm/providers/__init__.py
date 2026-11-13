"""Cloud providers.

A provider is anything that implements the methods below. The engine never
talks to a cloud API directly, which is what keeps the design portable.

    snapshot()                              -> provider-neutral environment dict
    lookup_change(resource_id, events)      -> who/when/what from the audit trail
    remediate(control, resource_id)         -> restore the approved setting
    list_vulnerabilities()                  -> scanner findings
    create_snapshot(instance_id)            -> snapshot id
    stop_services / start_services(instance_id, services)
    install_patches(instance_id)
    health_check(instance_id, services)     -> (ok, detail)
    restore_snapshot(instance_id, snapshot_id)
    send_notification(recipient, subject, body)
    poll_drift_events()                     -> change events pushed by the cloud
"""


class NotAutomatable(Exception):
    """Raised when a fix needs a person (for example registering an MFA device)."""
