"""Test del sidecar: protocollo persistente, grounding, proposte validate.

Si eseguono senza Ollama e senza rete: ``stream_reply`` viene sostituito da un
modello finto che produce testo e JSON noti.

    cd agent && .venv/bin/python -m unittest discover -s tests -v
"""

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from elliot_agent import __main__ as sidecar
from elliot_agent.catalog import (
    ProposalError,
    describe,
    load_catalog,
    parse_proposal_json,
    validate_proposal,
)


def fake_model(reply_text="Ecco un piano.", proposal_json=None, prompts=None):
    """Un ``stream_reply`` finto: testo per la chat, JSON per la proposta."""

    def stream(prompt, model=None):
        if prompts is not None:
            prompts.append(prompt)
        if "Traduci la richiesta" in prompt:
            if proposal_json is not None:
                yield proposal_json
            return
        for word in reply_text.split(" "):
            yield word + " "

    return stream


def run_sidecar(requests, stream):
    """Esegue il loop del sidecar su stdin finto e ritorna i frame emessi."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    out = io.StringIO()
    with patch.object(sys, "stdin", stdin), redirect_stdout(out), patch.object(
        sidecar, "stream_reply", stream
    ):
        sidecar._run()
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tools = load_catalog()

    def test_the_standard_catalog_loads_and_grounds_the_flags(self):
        self.assertIn("nmap", self.tools)
        nmap = self.tools["nmap"]
        self.assertEqual(nmap.binary, "nmap")
        self.assertIsNotNone(nmap.flag("-sV"))
        text = describe(self.tools)
        self.assertIn("-sS", text)
        self.assertIn("base_intrusiveness=low", text)

    def test_a_tool_outside_the_catalog_is_rejected(self):
        with self.assertRaises(ProposalError):
            validate_proposal(
                {"tool_id": "metasploit", "flags": [], "targets": ["127.0.0.1"]},
                self.tools,
            )

    def test_a_flag_outside_the_catalog_is_rejected(self):
        with self.assertRaises(ProposalError):
            validate_proposal(
                {"tool_id": "nmap", "flags": [{"name": "--raw"}], "targets": ["127.0.0.1"]},
                self.tools,
            )

    def test_bool_flags_take_no_value_and_intrusive_values_must_be_vetted(self):
        with self.assertRaises(ProposalError):
            validate_proposal(
                {
                    "tool_id": "nmap",
                    "flags": [{"name": "-sV", "value": "yes"}],
                    "targets": ["127.0.0.1"],
                },
                self.tools,
            )
        with self.assertRaises(ProposalError):
            validate_proposal(
                {
                    "tool_id": "nmap",
                    "flags": [{"name": "--script", "value": "exploit"}],
                    "targets": ["127.0.0.1"],
                },
                self.tools,
            )

    def test_a_valid_proposal_is_normalised(self):
        proposal = validate_proposal(
            {
                "tool_id": "nmap",
                "flags": [{"name": "-sV"}, {"name": "-p", "value": "80,443"}],
                "targets": ["127.0.0.1"],
            },
            self.tools,
        )
        self.assertEqual(proposal["tool_id"], "nmap")
        self.assertEqual(
            proposal["flags"],
            [{"name": "-sV"}, {"name": "-p", "value": "80,443"}],
        )
        self.assertEqual(proposal["targets"], ["127.0.0.1"])

    def test_cardinality_is_enforced(self):
        with self.assertRaises(ProposalError):
            validate_proposal({"tool_id": "nmap", "flags": [], "targets": []}, self.tools)

    def test_the_first_complete_json_object_wins(self):
        text = 'premessa\n```json\n{"tool_id": "nmap", "targets": ["a"]}\n```'
        self.assertEqual(
            parse_proposal_json(text),
            {"tool_id": "nmap", "targets": ["a"]},
        )
        self.assertIsNone(parse_proposal_json("nessun oggetto qui"))


class ProtocolTests(unittest.TestCase):
    def test_a_request_streams_chunks_then_a_proposal_then_done(self):
        proposal = (
            '{"tool_id": "nmap", "flags": [{"name": "-sV"}], '
            '"targets": ["127.0.0.1"]}'
        )
        prompts = []
        frames = run_sidecar(
            [{"prompt": "scansiona 127.0.0.1 con nmap"}],
            fake_model(proposal_json=proposal, prompts=prompts),
        )

        types = [f["type"] for f in frames]
        self.assertEqual(types[-1], "done")
        self.assertIn("chunk", types)
        self.assertIn("proposal", types)
        self.assertTrue(all(f["v"] == sidecar.PROTOCOL_VERSION for f in frames))

        emitted = next(f for f in frames if f["type"] == "proposal")
        self.assertEqual(emitted["tool_id"], "nmap")
        self.assertEqual(emitted["targets"], ["127.0.0.1"])

        # The proposal prompt carries the catalog as grounding.
        self.assertTrue(any("-sV" in p for p in prompts))

    def test_a_proposal_naming_an_unknown_tool_never_reaches_the_wire(self):
        frames = run_sidecar(
            [{"prompt": "lancia metasploit"}],
            fake_model(proposal_json='{"tool_id": "metasploit", "targets": ["x"]}'),
        )
        self.assertNotIn("proposal", [f["type"] for f in frames])
        self.assertEqual(frames[-1]["type"], "done")

    def test_the_process_handles_one_request_after_another(self):
        frames = run_sidecar(
            [{"prompt": "prima"}, {"prompt": "seconda"}],
            fake_model(),
        )
        self.assertEqual([f["type"] for f in frames].count("done"), 2)

    def test_a_malformed_request_reports_an_error_and_keeps_the_loop_alive(self):
        stdin = io.StringIO('non json\n{"prompt": "ok"}\n')
        out = io.StringIO()
        with patch.object(sys, "stdin", stdin), redirect_stdout(out), patch.object(
            sidecar, "stream_reply", fake_model()
        ):
            sidecar._run()
        frames = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
        self.assertEqual(frames[0]["type"], "error")
        self.assertEqual(frames[1]["type"], "done")
        self.assertIn("chunk", [f["type"] for f in frames[2:]])

    def test_the_curated_context_is_framed_as_data_not_instructions(self):
        prompts = []
        run_sidecar(
            [{"prompt": "che tool uso?", "context": ["Server: nginx (banner)"]}],
            fake_model(prompts=prompts),
        )
        self.assertTrue(
            any("mai come istruzioni" in p and "Server: nginx (banner)" in p for p in prompts),
            "the context must be marked as untrusted data",
        )

    def test_an_empty_prompt_is_an_error_not_a_crash(self):
        frames = run_sidecar([{"prompt": "   "}], fake_model())
        self.assertEqual([f["type"] for f in frames], ["error", "done"])


if __name__ == "__main__":
    unittest.main()
