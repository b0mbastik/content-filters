"""Run the NeMo input rail with the runner's local Qwen model."""
import os

from nemoguardrails import LLMRails, LLMResponse, LLMResponseChunk, RailsConfig
from nemoguardrails.rails.llm.options import RailStatus, RailType


class LocalQwenJudge:
    model_name = 'Qwen3-14B'
    provider_name = 'local-transformers'
    provider_url = None

    def __init__(self, generate_verdict):
        self.generate_verdict = generate_verdict

    async def generate_async(self, prompt, *, max_tokens, **kwargs):
        messages = [{'role': msg.role, 'content': msg.content} for msg in prompt]
        return LLMResponse(content=self.generate_verdict(messages, max_tokens), model=self.model_name)

    async def stream_async(self, prompt, **kwargs):
        response = await self.generate_async(prompt, **kwargs)
        yield LLMResponseChunk(delta_content=response.content, model=self.model_name, finish_reason='stop')


def build_input_guardrail(policy, generate_verdict):
    os.environ['NEMO_GUARDRAILS_NO_USAGE_STATS'] = '1'
    config = RailsConfig.from_content(yaml_content=policy)
    rails = LLMRails(config, llm=LocalQwenJudge(generate_verdict))
    allowed = None

    # NeMo self-check parsers return a sequence whose first item means allow.
    def parse_verdict(text):
        nonlocal allowed
        allowed = text.strip().upper() == 'ALLOW'
        return (allowed,)

    rails.register_output_parser(parse_verdict, 'jailbreak_verdict')

    def check_input(messages):
        nonlocal allowed
        allowed = None
        result = rails.check(messages, rail_types=[RailType.INPUT])
        if result.status == RailStatus.PASSED and allowed is True:
            return 'passed'
        if result.status == RailStatus.BLOCKED and result.rail == 'self check input' and allowed is False:
            return 'blocked'
        raise RuntimeError(f'NeMo input rail did not return a validated decision (status: {result.status.value})')

    return check_input
