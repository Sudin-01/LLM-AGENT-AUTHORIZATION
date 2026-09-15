# Enforcing Tool Permissions on Autonomous LLM Agents

Code, data and reproduction pipeline for *A Measured Comparison of Four Authorization Architectures*.

Autonomous agents built on large language models can transfer funds, delete records and run commands. The permission systems that gate those actions are usually mutable process state, which leaves no trustworthy record of what was allowed or why. This repository asks where an agent's authorization should live, and measures four backends on the same prompts, the same classified actions and the same attacks.

Internally the implementation is called BlockGuard, and that name appears in file and variable names.

## Systems compared

| System | Where authorization lives | Implementation |
|---|---|---|
| A | Nowhere (baseline, every request allowed) | `backend/policy_engine.py`, mode A |
| B | In-process policy store (Python dictionary) | `backend/policy_engine.py`, mode B |
| C | Smart contract on an Ethereum Virtual Machine | `contracts/AgentPermissionRegistry.sol`, mode C |
| D | Signed hash-chained audit log with periodic Merkle anchoring | `experiments/run_systemd_experiment.py` |
| E | Open Policy Agent 1.20.1 evaluating an equivalent Rego policy | `experiments/opa/policy.rego`, `experiments/run_opa_experiment.py` |

A, B and C run the full 900-trial sweeps: 300 prompts against each of the three configurations. E is evaluated on the same classified actions and the same attacks. D answers the audit-integrity question and is evaluated on the attacks and on gas cost. It is not run through the conformance sweeps.

Every request passes through the same pipeline:

```
User interface -> AI agent (intent classifier) -> Policy engine -> Backend check -> Action executor -> Audit log
```

The dataset has 300 prompts for three agents (`agent_a`, `agent_b`, `agent_c`) and five action types (`search_web`, `read_file`, `execute_command`, `delete_database`, `transfer_money`). Of these, 180 prompts should be denied and 120 allowed.

## Main results

- **The enforcement backend does not bound safety.** Under matched policies, Systems B, C and E return identical conformance (242/300 with the rule-based classifier) and identical sets of leaked trials. A trial-level decomposition attributes all observed leakage to intent classification and none to enforcement.
- **Classification is the binding constraint when it must be cheap.** End-to-end conformance is 80.67% with a rule-based classifier and 82.67% with a sentence-embedding classifier (McNemar p = 0.54). An LLM classifier reaches 99.00% accuracy and 99.33% conformance, with none of the 180 restricted requests leaked. Its median cost is 839 ms per decision, against 19.5 ms for the embedding classifier and 0.032 ms for the rule-based one.
- **Open Policy Agent is the fastest backend.** Its median decision takes 0.186 ms, against 0.61 ms for the in-process store and 21.06 ms for the on-chain check.
- **The backends separate only under policy manipulation.** Across four attack scenarios repeated 30 times each, only System C, whose write-authorization sits off the compromised host, blocks unauthorized escalation (30/30) and records an insider's escalation-and-revert (30/30). Systems B and E detect it in 0/30 repetitions.
- **A signed hash chain protects the log, not the policy.** With anchoring every 10 decisions, System D detects an audit-log wipe in 30/30 repetitions at 3,032 gas per decision, against 35,452 for per-decision on-chain logging. It detects no policy tampering at any anchoring interval, because an adversary on the host bypasses the log rather than forging it.

## Check the reported numbers

No chain or network is needed. This recomputes every reported figure from the committed data and exits non-zero if any fails to match:

```bash
python -m pip install -r experiments/requirements.txt
python experiments/verify_paper_numbers.py
```

A clean run ends with `RESULT: 116/116 checks reproduce from committed data`.

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.12 (tested on 3.12.2) | everything |
| Node.js | 18 or later | contract compilation, deployment, tests |
| Ganache | 7 or later (`npm install -g ganache`) | local chain |
| Open Policy Agent | 1.20.1 (`brew install opa`) | System E only |

`experiments/requirements.txt` pins the full Python working set. The pins matter: an unpinned `sentence-transformers` pulls a `transformers` release that requires `torch>=2.5`, which fails at import against torch 2.2.

## Full reproduction

```bash
python -m pip install -r experiments/requirements.txt
npm install
./scripts/reproduce.sh
```

This starts a fresh local chain, runs every experiment, verifies the output and regenerates the figures, in about 15 minutes. Individual stages:

| Command | What it runs |
|---|---|
| `./scripts/reproduce.sh sweeps` | 900-trial sweeps with the rule-based and embedding classifiers |
| `./scripts/reproduce.sh ablation` | Matched-policy ablation (three configurations) |
| `./scripts/reproduce.sh offline` | Offline classifier comparison, dataset diversity audit, and the LLM projection check |
| `./scripts/reproduce.sh opa` | System E (skipped if `opa` is not installed) |
| `./scripts/reproduce.sh tamper` | Tamper resistance, four attacks with 30 repetitions each |
| `./scripts/reproduce.sh gemini` | Re-queries the LLM classifier (needs `GEMINI_API_KEY`) |
| `./scripts/reproduce.sh verify` | Recomputes every reported number from the CSVs |
| `./scripts/reproduce.sh figures` | Regenerates all figures |

Set `PYTHON` to choose the interpreter.

## Experiments and data

All scripts are in `experiments/`.

| Experiment | Script | Output |
|---|---|---|
| Sweep, rule-based classifier | `run_experiments.py --dataset v2` | `results_v2_rule/` |
| Sweep, embedding classifier | `run_experiments.py --dataset v2` | `results_v2/` |
| Sweep, LLM classifier (replayed predictions) | `run_experiments.py --dataset v2` | `results_v2_gemini_sweep/` |
| Matched-policy ablation | `run_ablation.py --dataset v2` | `results_v2_ablation/` |
| Offline classifier comparison | `run_classifier_comparison.py --dataset v2` | `results_v2_clf/` |
| LLM classifier predictions and projection check | `run_gemini_resume.py`, `analyze_m3_gemini.py` | `results_v2_gemini/` |
| Dataset diversity audit | `audit_dataset_diversity.py` | `results_dataset_v2/` |
| System E, Open Policy Agent | `run_opa_experiment.py` | `results_opa/` |
| Tamper resistance, Systems B and C | `run_tamper_experiment.py` | `results_tamper/` |
| System D, hash chain with Merkle anchoring | `run_systemd_experiment.py` | `results_systemd/` |
| Availability under RPC faults, asynchronous audit writes | `run_availability_experiment.py` | `results_availability/` |
| Public testnet (Sepolia), two sessions | `../scripts/measure_sepolia.js` | `results_sepolia/`, `results_sepolia_s2/` |
| Static analysis (Slither) | | `results_security/slither.txt` |

The 300-prompt dataset is defined in `experiments/prompt_dataset.py`. It is deterministic, so a fresh run reproduces the committed decision-level CSVs exactly.

### The LLM classifier arm

The LLM classifier's 300 predictions are recorded in `experiments/results_v2_gemini/classifier_comparison.csv`. The third sweep runs against the chain with `CLASSIFIER_TYPE=replay`, which returns those recorded predictions instead of calling the API. It therefore needs no API key and gives identical decisions on every run. The replay classifier raises an error on any prompt it has no recording for, rather than silently falling back to another classifier.

```bash
npx hardhat run scripts/deploy.js --network ganache
(cd backend && USE_TF=0 CLASSIFIER_TYPE=replay python app.py) &
mkdir -p experiments/results_v2_gemini_sweep
(cd experiments/results_v2_gemini_sweep && USE_TF=0 python ../run_experiments.py --dataset v2)
```

### Public testnet measurements

The Sepolia deployment identifiers are withheld during anonymous review. In `results_sepolia*/`, the `tx_hash` column reads `withheld`, and block numbers are given relative to the first block of session 1. Every measured latency and gas value is complete and unchanged. To run a new session against your own deployment:

```bash
export SEPOLIA_URL=<a Sepolia RPC endpoint>
export PRIVATE_KEY=<a funded Sepolia test key>
export SEPOLIA_CONTRACT=<your deployed contract address>
SEPOLIA_SESSION=s3 npx hardhat run scripts/measure_sepolia.js --network sepolia
```

### Ordering constraint

`run_ablation.py` rewrites the agents' permissions and leaves the last configuration in place. Re-seed the policy before running any other experiment:

```bash
npx hardhat run scripts/deploy.js --network ganache
```

`run_experiments.py` checks the policy baseline before it starts and aborts if it has drifted. `scripts/reproduce.sh` handles the ordering automatically.

### What reproduces exactly

Decision-level results reproduce exactly: conformance, DENY-leakage, per-tool and per-stratum breakdowns, leaked-trial overlap, McNemar statistics, the ablation, the diversity audit and every tamper outcome.

Two quantities depend on the host and will vary:

- **Latency** depends on machine load and chain length. A freshly deployed chain gives a System C median near 22 ms. A chain already holding about 5,000 blocks gives about 35 ms.
- **Mean gas** depends on how many storage slots are cold. The median is stable.

The verification script checks these with tolerances and everything else exactly.

## Running the system interactively

```bash
# Terminal 1: local chain
ganache --server.port 8545 --chain.chainId 1337 \
  --wallet.mnemonic "test test test test test test test test test test test junk"

# Terminal 2: deploy the contract and start the API
npm install
npx hardhat run scripts/deploy.js --network ganache
pip install -r backend/requirements.txt -r backend/requirements_classifiers.txt
cd backend && python app.py        # http://localhost:5000
```

Then open `blockguard-app.html` in a browser.

| Variable | Effect |
|---|---|
| `CLASSIFIER_TYPE` | `rule` (default), `embedding`, `gemini` (needs `GEMINI_API_KEY`) or `replay` |
| `OPENAI_API_KEY` | Optional. Used only for the agent's natural-language explanation, which never affects the decision |
| `BLOCKGUARD_DATA_DIR` | Where the SQLite audit mirror and scratch files are written (default: system temp directory) |

### API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health |
| `POST` | `/api/request` | Submit an agent request (`request`, `agent_id`, `mode`) |
| `GET` | `/api/audit` | Audit log |
| `GET` | `/api/stats` | Aggregate statistics |
| `GET` | `/api/policy/<agent>` | Read an agent's policy |
| `PUT` | `/api/policy/<agent>` | Update an agent's policy |
| `GET` | `/api/blockchain/info` | Chain and contract status |
| `POST` | `/api/experiment/run` | Run the benchmark |
| `GET` | `/api/experiment/results` | Cached benchmark results |

## Contract tests

```bash
npx hardhat test
```

`test/AgentPermissionRegistry.test.js` covers permission setting and revocation, owner-only access control, decision logging and ownership transfer. `test/SecurityInvariants.test.js` checks seven security invariants.

## Keys in this repository

Every private key in the code is a standard, publicly documented Hardhat and Ganache development key derived from the `test ... junk` mnemonic. None of them holds value on any real network.
