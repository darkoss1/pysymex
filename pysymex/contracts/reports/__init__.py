# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Contract report adapters and summaries."""

from __future__ import annotations

from pysymex.contracts.reports.adapters import extract_counterexample_from_model
from pysymex.contracts.reports.evidence import (
    EVIDENCE_REPORT_SCHEMA,
    contract_evidence_for_issue,
    contract_evidence_for_result,
    contract_evidence_to_dict,
    not_verified_reasons_for_result,
    verified_result_evidence_dict,
    verified_results_evidence_report,
)
from pysymex.contracts.reports.summary import (
    RuntimeContractSummary,
    aggregate_runtime_contract_outcomes,
)

__all__ = [
    "EVIDENCE_REPORT_SCHEMA",
    "RuntimeContractSummary",
    "aggregate_runtime_contract_outcomes",
    "contract_evidence_for_issue",
    "contract_evidence_for_result",
    "contract_evidence_to_dict",
    "extract_counterexample_from_model",
    "not_verified_reasons_for_result",
    "verified_result_evidence_dict",
    "verified_results_evidence_report",
]
