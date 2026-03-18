from typing import Optional, Dict, Any

from .shields import InputShield_L5, OutputShield_L5
from .openclay_report import (
    create_report,
    update_section,
    set_final_action,
    save_report,
)


class OpenClayBoundary:
    """
    OpenClay execution boundary.

    Owns:
    - calling InputShield
    - calling the model
    - calling OutputShield
    - creating & saving OpenClay reports

    The demo app calls ONLY this class.
    """

    def __init__(
        self,
        model_runner,
        input_shield: Optional[InputShield_L5] = None,
        output_shield: Optional[OutputShield_L5] = None,
        shield_level: str = "L5",
        model_name: str = "unknown",
    ):
        """
        model_runner: callable(system_prompt, user_input) -> model_output
        """
        self.model_runner = model_runner
        self.input_shield = input_shield or InputShield_L5()
        self.output_shield = output_shield or OutputShield_L5()
        self.shield_level = shield_level
        self.model_name = model_name

    def run(
        self,
        attack_id: str,
        attack_category: str,
        user_input: str,
        system_prompt: str,
    ) -> Dict[str, Any]:
        """
        Execute a single request through OpenClay.

        Returns:
            {
              "blocked": bool,
              "output": str | None,
              "reason": str | None
            }
        """

        # -------------------------------------------------
        # 1. Create OpenClay Security Report
        # -------------------------------------------------
        report = create_report(
            attack_id=attack_id,
            attack_category=attack_category,
            shield_level=self.shield_level,
            model_name=self.model_name,
        )

        # -------------------------------------------------
        # 2. Input Shield
        # -------------------------------------------------
        input_result = self.input_shield.run(
            user_input=user_input,
            system_prompt=system_prompt,
        )

        update_section(report, "input_shield", {
            "blocked": input_result["block"],
            "reason": input_result.get("reason"),
            "signals": {
                "pattern_match": input_result.get("reason") == "pattern_match",
                "semantic_match": input_result.get("reason") == "semantic_match",
                "complexity_score": input_result.get("score"),
            },
            "canary_inserted": not input_result["block"],
            "canary_value": input_result.get("canary"),
        })

        # -------------------------------------------------
        # 3. Blocked at Input
        # -------------------------------------------------
        if input_result["block"]:
            set_final_action(report, "BLOCK")
            save_report(report)

            return {
                "blocked": True,
                "output": None,
                "reason": input_result.get("reason"),
            }

        # -------------------------------------------------
        # 4. Run Model
        # -------------------------------------------------
        secured_system_prompt = input_result["secured_system_prompt"]
        canary = input_result["canary"]

        model_output = self.model_runner(
            secured_system_prompt,
            user_input,
        )

        update_section(report, "model_execution", {
            "system_prompt_used": "<redacted>",
            "user_input": user_input,
            "raw_model_output": model_output,
        })

        # -------------------------------------------------
        # 5. Output Shield
        # -------------------------------------------------
        output_result = self.output_shield.run(
            model_output=model_output,
            canary=canary,
        )

        update_section(report, "output_shield", {
            "blocked": output_result["block"],
            "reason": output_result.get("reason"),
            "canary_detected": output_result.get("reason") == "canary_leak",
            "pii_findings": output_result.get("details", []),
        })

        # -------------------------------------------------
        # 6. Final Decision
        # -------------------------------------------------
        if output_result["block"]:
            set_final_action(report, "BLOCK")
            save_report(report)

            return {
                "blocked": True,
                "output": None,
                "reason": output_result.get("reason"),
            }

        set_final_action(report, "ALLOW")
        save_report(report)

        return {
            "blocked": False,
            "output": output_result["output"],
            "reason": None,
        }
