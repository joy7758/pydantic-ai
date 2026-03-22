<!-- language-switch:start -->
[English](./README.md) | [中文](./README.zh-CN.md)
<!-- language-switch:end -->

<div align="center">
<a href="https://ai.pydantic.dev/">
<picture>
<source media="(首选颜色方案：深色)" srcset="https://ai.pydantic.dev/img/pydantic-ai-dark.svg">
<img src="https://ai.pydantic.dev/img/pydantic-ai-light.svg" alt="Pydantic AI">
</picture>
</a>
</div>
<div align="center">
<h3>GenAI 智能体框架，Pydantic方式</h3>
</div>
<div align="center">
<a href="https://github.com/pydantic/pydantic-ai/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://github.com/pydantic/pydantic-ai/actions/workflows/ci.yml/badge.svg?event=push" alt="CI"></a>
<a href="https://coverage-badge.samuelcolvin.workers.dev/redirect/pydantic/pydantic-ai"><img src="https://coverage-badge.samuelcolvin.workers.dev/pydantic/pydantic-ai.svg" alt="Coverage"></a>
<a href="https://pypi.python.org/pypi/pydantic-ai"><img src="https://img.shields.io/pypi/v/pydantic-ai.svg" alt="PyPI"></a>
<a href="https://github.com/pydantic/pydantic-ai"><img src="https://img.shields.io/pypi/pyversions/pydantic-ai.svg" alt="versions"></a>
<a href="https://github.com/pydantic/pydantic-ai/blob/main/LICENSE"><img src="https://img.shields.io/github/license/pydantic/pydantic-ai.svg?v" alt="license"></a>
<a href="https://logfire.pydantic.dev/docs/join-slack/"><img src="https://img.shields.io/badge/Slack-Join%20Slack-4A154B?logo=slack" alt="Join Slack" /></a>
</div>

---

**文档**：[ai.pydantic.dev](https://ai.pydantic.dev/)

---

### <em>Pydantic AI 是一个 Python 代理框架，旨在帮助您使用生成式 AI 快速、自信、轻松地构建生产级应用程序和工作流程。</em>


FastAPI 通过提供创新且符合人体工程学的设计，建立在 [Pydantic Validation](https://docs.pydantic.dev) 和现代 Python 功能（如类型提示）的基础上，彻底改变了 Web 开发。

然而，尽管几乎每个 Python 代理框架和 LLM 库都使用 Pydantic Validation，但当我们开始在 [Pydantic Logfire](https://pydantic.dev/logfire) 中使用 LLM 时，我们找不到任何给我们同样感觉的东西。

我们构建 Pydantic AI 的目的很简单：将 FastAPI 的感觉带入 GenAI 应用程序和代理开发中。

## 为什么使用 Pydantic AI

1. **由 Pydantic 团队构建**：
[Pydantic Validation](https://docs.pydantic.dev/latest/) 是 OpenAI SDK、Google ADK、Anthropic SDK、LangChain、LlamaIndex、AutoGPT、Transformers、CrewAI、Instructor 等的验证层。 _当你可以直接找到源头时为什么要使用导数？_ :smiley:

2. **与模型无关**：
支持几乎所有[模型](https://ai.pydantic.dev/models/overview) 和提供商：OpenAI、Anthropic、Gemini、DeepSeek、Grok、Cohere、Mistral 和 Perplexity； Azure AI Foundry、Amazon Bedrock、Google Vertex AI、Ollama、LiteLLM、Groq、OpenRouter、Together AI、Fireworks AI、Cerebras、Hugging Face、GitHub、Heroku、Vercel、Nebius、OVHcloud、阿里云、SambaNova 和 Outlines。如果您最喜欢的模型或提供商未列出，您可以轻松实现[自定义模型](https://ai.pydantic.dev/models/overview#custom-models)。

3. **无缝可观察性**：
与我们的通用 OpenTelemetry 可观测平台 [Pydantic Logfire](https://pydantic.dev/logfire) 紧密[集成](https://ai.pydantic.dev/logfire)，用于实时调试、基于评估的性能监控以及行为、跟踪和成本跟踪。如果您已经有支持 OTel 的可观测平台，您也可以[使用它](https://ai.pydantic.dev/logfire#alternative-observability-backends)。

4. **完全类型安全**：
旨在为您的 IDE 或 AI 编码代理提供尽可能多的上下文，以进行自动完成和[类型检查](https://ai.pydantic.dev/agents#static-type-checking)，将整个错误类从运行时转移到写入时，以获得一点 Rust 的“如果它能编译，它就能工作”的感觉。

5. **强大的评估**：
使您能够系统地测试和[评估](https://ai.pydantic.dev/evals)您构建的代理系统的性能和准确性，并在 Pydantic Logfire 中监控一段时间内的性能。

6. **MCP、A2A 和 UI**：
集成[模型上下文协议](https://ai.pydantic.dev/mcp/overview)、[Agent2Agent](https://ai.pydantic.dev/a2a)和各种[UI事件流](https://ai.pydantic.dev/ui/overview)标准，使您的代理能够访问外部工具和数据，使其与其他代理进行互操作，并通过基于流事件的通信构建交互式应用程序。

7. **人在环工具批准**：
您可以轻松标记某些工具调用[需要批准](https://ai.pydantic.dev/deferred-tools#human-in-the-loop-tool-approval)，然后才能继续，这可能取决于工具调用参数、对话历史记录或用户首选项。

8. **持久执行**：
使您能够构建[持久代理](https://ai.pydantic.dev/durable_execution/overview/)，该代理可以在短暂的 API 故障和应用程序错误或重新启动时保留其进度，并以生产级可靠性处理长时间运行、异步和人机交互的工作流程。

9. **流式输出**：
提供连续[流](https://ai.pydantic.dev/output#streamed-results)结构化输出的能力，并立即验证，确保实时访问生成的数据。

10. **图形支持**：
提供了一种使用类型提示定义[图表](https://ai.pydantic.dev/graph)的强大方法，适用于标准控制流可能降级为意大利面条代码的复杂应用程序。

但实际上，没有任何列表比[尝试一下](#next-steps) 并看看它给您带来的感受更令人信服！

## 你好世界示例

这是 Pydantic AI 的一个最小示例：

```python
from pydantic_ai import Agent

# Define a very simple agent including the model to use, you can also set the model when running the agent.
agent = Agent(
    'anthropic:claude-sonnet-4-6',
    # Register static instructions using a keyword argument to the agent.
    # For more complex dynamically-generated instructions, see the example below.
    instructions='Be concise, reply with one sentence.',
)

# Run the agent synchronously, conducting a conversation with the LLM.
result = agent.run_sync('Where does "hello world" come from?')
print(result.output)
"""
The first known use of "hello, world" was in a 1974 textbook about the C programming language.
"""
```

_（此示例已完成，它可以“按原样”运行，假设您已[安装了 `pydantic_ai` 软件包](https://ai.pydantic.dev/install))_

交流会非常短：Pydantic AI 会将指令和用户提示发送给 LLM，模型将返回文本响应。

还不是很有趣，但我们可以轻松添加[工具](https://ai.pydantic.dev/tools)、[动态指令](https://ai.pydantic.dev/agents#instructions)和[结构化输出](https://ai.pydantic.dev/output)来构建更强大的智能体。

## 工具和依赖注入示例

下面是一个使用 Pydantic AI 为银行构建支持智能体的简洁示例：

**（更好的文档示例[在文档中](https://ai.pydantic.dev/#tools-dependency-injection-example)）**

```python
from dataclasses import dataclass

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from bank_database import DatabaseConn


# SupportDependencies is used to pass data, connections, and logic into the model that will be needed when running
# instructions and tool functions. Dependency injection provides a type-safe way to customise the behavior of your agents.
@dataclass
class SupportDependencies:
    customer_id: int
    db: DatabaseConn


# This Pydantic model defines the structure of the output returned by the agent.
class SupportOutput(BaseModel):
    support_advice: str = Field(description='Advice returned to the customer')
    block_card: bool = Field(description="Whether to block the customer's card")
    risk: int = Field(description='Risk level of query', ge=0, le=10)


# This agent will act as first-tier support in a bank.
# Agents are generic in the type of dependencies they accept and the type of output they return.
# In this case, the support agent has type `Agent[SupportDependencies, SupportOutput]`.
support_agent = Agent(
    'openai:gpt-5.2',
    deps_type=SupportDependencies,
    # The response from the agent will, be guaranteed to be a SupportOutput,
    # if validation fails the agent is prompted to try again.
    output_type=SupportOutput,
    instructions=(
        'You are a support agent in our bank, give the '
        'customer support and judge the risk level of their query.'
    ),
)


# Dynamic instructions can make use of dependency injection.
# Dependencies are carried via the `RunContext` argument, which is parameterized with the `deps_type` from above.
# If the type annotation here is wrong, static type checkers will catch it.
@support_agent.instructions
async def add_customer_name(ctx: RunContext[SupportDependencies]) -> str:
    customer_name = await ctx.deps.db.customer_name(id=ctx.deps.customer_id)
    return f"The customer's name is {customer_name!r}"


# The `tool` decorator let you register functions which the LLM may call while responding to a user.
# Again, dependencies are carried via `RunContext`, any other arguments become the tool schema passed to the LLM.
# Pydantic is used to validate these arguments, and errors are passed back to the LLM so it can retry.
@support_agent.tool
async def customer_balance(
        ctx: RunContext[SupportDependencies], include_pending: bool
) -> float:
    """Returns the customer's current account balance."""
    # The docstring of a tool is also passed to the LLM as the description of the tool.
    # Parameter descriptions are extracted from the docstring and added to the parameter schema sent to the LLM.
    balance = await ctx.deps.db.customer_balance(
        id=ctx.deps.customer_id,
        include_pending=include_pending,
    )
    return balance


...  # In a real use case, you'd add more tools and a longer system prompt


async def main():
    deps = SupportDependencies(customer_id=123, db=DatabaseConn())
    # Run the agent asynchronously, conducting a conversation with the LLM until a final response is reached.
    # Even in this fairly simple case, the agent will exchange multiple messages with the LLM as tools are called to retrieve an output.
    result = await support_agent.run('What is my balance?', deps=deps)
    # The `result.output` will be validated with Pydantic to guarantee it is a `SupportOutput`. Since the agent is generic,
    # it'll also be typed as a `SupportOutput` to aid with static type checking.
    print(result.output)
    """
    support_advice='Hello John, your current account balance, including pending transactions, is $123.45.' block_card=False risk=1
    """

    result = await support_agent.run('I just lost my card!', deps=deps)
    print(result.output)
    """
    support_advice="I'm sorry to hear that, John. We are temporarily blocking your card to prevent unauthorized transactions." block_card=True risk=8
    """
```

## 下一步

要亲自尝试 Pydantic AI，请[安装它](https://ai.pydantic.dev/install) 并按照[示例中](https://ai.pydantic.dev/examples/setup) 中的说明进行操作。

阅读[文档](https://ai.pydantic.dev/agents/)，了解有关使用 Pydantic AI 构建应用程序的更多信息。

阅读[API参考](https://ai.pydantic.dev/api/agent/)以了解Pydantic AI的接口。

如果您有任何疑问，请加入 [Slack](https://logfire.pydantic.dev/docs/join-slack/) 或在 [GitHub](https://github.com/pydantic/pydantic-ai/issues) 上提交问题。
