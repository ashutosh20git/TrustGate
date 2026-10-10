"""Build a Pydantic argument model for a gated tool, including the reserved fields."""

from __future__ import annotations

import inspect
from typing import Any, Literal

from pydantic import BaseModel, Field, create_model

from trustgate.gate import RegisteredTool
from trustgate.tiers import Tier


def args_model(tool: RegisteredTool) -> type[BaseModel]:
    fields: dict[str, Any] = {}
    if tool.fn is not None:
        for name, param in inspect.signature(tool.fn).parameters.items():
            if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                continue
            annotation = param.annotation if param.annotation is not inspect.Parameter.empty else str
            default = param.default if param.default is not inspect.Parameter.empty else ...
            fields[name] = (annotation, default)
    required = tool.tier >= Tier.SECURITY_REDUCING
    fields["verdict"] = (Literal["malicious", "benign", "unsure"],
                         Field(... if required else "unsure", description="Your verdict on the alert."))
    fields["cited_evidence"] = (list[str], Field(... if required else [],
                                description="Evidence IDs (ev-N) and typed facts (facts.<name>) that justify this action."))
    fields["rationale"] = (str, Field("", max_length=800))
    if "alert_id" not in fields:
        fields["alert_id"] = (str, Field("", description="ID of the alert this action is about."))
    return create_model(f"{tool.name}_args", **fields)
