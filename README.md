# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/isaacschepp/agent-inject/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                     |    Stmts |     Miss |   Branch |   BrPart |       Cover |   Missing |
|--------------------------------------------------------- | -------: | -------: | -------: | -------: | ----------: | --------: |
| src/agent\_inject/\_\_init\_\_.py                        |        2 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/\_\_init\_\_.py                |        3 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/base.py                        |       36 |        0 |        2 |        0 |     100.00% |           |
| src/agent\_inject/attacks/cross\_agent/\_\_init\_\_.py   |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/deputies/\_\_init\_\_.py       |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/direct/\_\_init\_\_.py         |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/function\_call/\_\_init\_\_.py |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/indirect/\_\_init\_\_.py       |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/loader.py                      |       73 |        0 |       18 |        0 |     100.00% |           |
| src/agent\_inject/attacks/mcp/\_\_init\_\_.py            |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/multimodal/\_\_init\_\_.py     |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/rag/\_\_init\_\_.py            |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/attacks/registry.py                    |       50 |        0 |       12 |        0 |     100.00% |           |
| src/agent\_inject/cli.py                                 |       95 |        0 |       18 |        0 |     100.00% |           |
| src/agent\_inject/config.py                              |      105 |        0 |       22 |        0 |     100.00% |           |
| src/agent\_inject/detection.py                           |        8 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/engine.py                              |       61 |        0 |       18 |        0 |     100.00% |           |
| src/agent\_inject/evasion/\_\_init\_\_.py                |        2 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/evasion/transforms.py                  |      110 |        0 |       12 |        0 |     100.00% |           |
| src/agent\_inject/exfiltration/\_\_init\_\_.py           |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/harness/\_\_init\_\_.py                |        2 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/harness/adapters/\_\_init\_\_.py       |        2 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/harness/adapters/rest.py               |       40 |        0 |        2 |        0 |     100.00% |           |
| src/agent\_inject/harness/base.py                        |       13 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/jailbreaks/\_\_init\_\_.py             |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/models.py                              |       86 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/paths.py                               |       12 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/persistence/\_\_init\_\_.py            |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/reports/\_\_init\_\_.py                |        0 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/scorers/\_\_init\_\_.py                |        2 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/scorers/base.py                        |      188 |        0 |       72 |        0 |     100.00% |           |
| src/agent\_inject/strategies/\_\_init\_\_.py             |        2 |        0 |        0 |        0 |     100.00% |           |
| src/agent\_inject/strategies/base.py                     |       48 |        0 |        2 |        0 |     100.00% |           |
| src/agent\_inject/strategies/crescendo.py                |       49 |        0 |        8 |        0 |     100.00% |           |
| **TOTAL**                                                |  **989** |    **0** |  **186** |    **0** | **100.00%** |           |


## Setup coverage badge

Below are examples of the badges you can use in your main branch `README` file.

### Direct image

[![Coverage badge](https://raw.githubusercontent.com/isaacschepp/agent-inject/python-coverage-comment-action-data/badge.svg)](https://htmlpreview.github.io/?https://github.com/isaacschepp/agent-inject/blob/python-coverage-comment-action-data/htmlcov/index.html)

This is the one to use if your repository is private or if you don't want to customize anything.

### [Shields.io](https://shields.io) Json Endpoint

[![Coverage badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/isaacschepp/agent-inject/python-coverage-comment-action-data/endpoint.json)](https://htmlpreview.github.io/?https://github.com/isaacschepp/agent-inject/blob/python-coverage-comment-action-data/htmlcov/index.html)

Using this one will allow you to [customize](https://shields.io/endpoint) the look of your badge.
It won't work with private repositories. It won't be refreshed more than once per five minutes.

### [Shields.io](https://shields.io) Dynamic Badge

[![Coverage badge](https://img.shields.io/badge/dynamic/json?color=brightgreen&label=coverage&query=%24.message&url=https%3A%2F%2Fraw.githubusercontent.com%2Fisaacschepp%2Fagent-inject%2Fpython-coverage-comment-action-data%2Fendpoint.json)](https://htmlpreview.github.io/?https://github.com/isaacschepp/agent-inject/blob/python-coverage-comment-action-data/htmlcov/index.html)

This one will always be the same color. It won't work for private repos. I'm not even sure why we included it.

## What is that?

This branch is part of the
[python-coverage-comment-action](https://github.com/marketplace/actions/python-coverage-comment)
GitHub Action. All the files in this branch are automatically generated and may be
overwritten at any moment.