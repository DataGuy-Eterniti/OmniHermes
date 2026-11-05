"""Tool schemas for Presence Gate.

These schemas define the tools exposed by Presence Gate to the Hermes LLM runtime.
"""

PRESENCE_STATUS_SCHEMA = {
    "name": "presence_status",
    "description": "Check the status of the Presence Gate security gate, including enrolled profile, desk presence, policy configuration, and cryptographic audit integrity.",
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

PRESENCE_ENROLL_SCHEMA = {
    "name": "presence_enroll",
    "description": "Enroll an owner's face for biometric authorization. Captures biometric embeddings locally on-device with zero raw images stored.",
    "parameters": {
        "type": "object",
        "properties": {
            "owner_name": {
                "type": "string",
                "description": "Name of the primary workstation owner to enroll (e.g. 'Elijah').",
            },
            "primary": {
                "type": "boolean",
                "description": "Whether this user is the primary workstation owner.",
            },
        },
        "required": ["owner_name"],
    },
}

PRESENCE_CONFIGURE_SCHEMA = {
    "name": "presence_configure",
    "description": "Update Presence Gate security policy settings, such as guarded tools, mode, and away timeout.",
    "parameters": {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "Enable or disable biometric gate enforcement.",
            },
            "mode": {
                "type": "string",
                "enum": ["strict", "cached_presence"],
                "description": "'strict' prompts every time; 'cached_presence' allows actions while continuous presence is detected.",
            },
            "away_timeout_seconds": {
                "type": "integer",
                "description": "Inactivity threshold in seconds before owner is marked AWAY and actions paused.",
            },
            "guarded_tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of tool names that require biometric authorization before execution.",
            },
        },
        "required": [],
    },
}

PRESENCE_AUDIT_LOGS_SCHEMA = {
    "name": "presence_audit_logs",
    "description": "Retrieve recent biometric authorization audit logs and verify the cryptographic integrity of the SHA-256 chain.",
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of recent audit records to return (default: 10).",
            },
            "verify_chain": {
                "type": "boolean",
                "description": "If true, mathematically verifies the cryptographic SHA-256 hash chain of all stored logs.",
            },
        },
        "required": [],
    },
}

PRESENCE_UNLOCK_SCHEMA = {
    "name": "presence_unlock",
    "description": "Launch interactive face verification in a relaxed 5-minute window and grant a temporary execution window (default 2 mins) for high-risk operations.",
    "parameters": {
        "type": "object",
        "properties": {
            "duration_seconds": {
                "type": "integer",
                "description": "Duration in seconds for the unlock window upon successful verification (default: 120s).",
            },
        },
        "required": [],
    },
}

# Backward compatibility aliases
OMNIHERMES_STATUS_SCHEMA = {
    **PRESENCE_STATUS_SCHEMA,
    "name": "omnihermes_status",
}
OMNIHERMES_ENROLL_SCHEMA = {
    **PRESENCE_ENROLL_SCHEMA,
    "name": "omnihermes_enroll",
}
OMNIHERMES_CONFIGURE_SCHEMA = {
    **PRESENCE_CONFIGURE_SCHEMA,
    "name": "omnihermes_configure",
}
OMNIHERMES_AUDIT_LOGS_SCHEMA = {
    **PRESENCE_AUDIT_LOGS_SCHEMA,
    "name": "omnihermes_audit_logs",
}
