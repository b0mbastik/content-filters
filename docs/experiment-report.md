# Prompt-injection protection in risk classification: experimental report

**Status:** Stages A, B and C completed. The results below use the revised protection-layer design and the available result files. All accuracy figures remain subject to independent review of the provisional labels.

## 1. Aim and main findings

The experiment examines whether attacker-written instructions embedded in imported incident material can change an LLM's assessment of information-security risk, and whether prompt-based protection layers reduce that effect. Stage C tests whether classifications match legitimate later evidence when attack-bearing text is also present.

The completed results suggest that the tested protections reduced attack success overall on this dataset. Without protection, a mean of **25 of 30 cases** reached the attacker's target after a correct clean assessment. This fell to **18.33** with P1 and **12** with P2. The improvement was concentrated in attacks targeting HIGH. Attacks targeting LOW remained effective, and P2 returned the provisionally incorrect LOW grade on a mean of **3.33 clean cases out of 30**. Its lower conditional attack-success count must therefore be interpreted alongside that loss of clean accuracy.

These findings apply to the specific synthetic incidents, attack templates, model and prompt versions tested. The expected labels are provisional and require independent review. In Stage C, all three layers classified the evidence-only condition correctly against provisional labels. When the attack-bearing text was added, evidence-based correctness was retained in 70.0% of paired trials for P0, 93.3% for P1 and 100% for P2. These are descriptive results for the tested cases, not evidence of the mechanism behind individual errors.

## 2. Dataset and task

The dataset contains 30 fictional university IT and information-security incident reports. Each original report has a provisional MEDIUM risk label under the supplied rubric. The rubric asks for the **current unresolved risk**, rather than an incident's historical peak, and defines LOW, MEDIUM and HIGH. A clean grading error is an output that differs from the provisional label; this is not a substitute for independent validation of that label.

Twelve synthetic attack templates are reused across the cases. Fifteen cases are assigned an attack requesting LOW and 15 an attack requesting HIGH. The attacker controls appended imported text, not the original incident facts, the rubric, labels, or model weights. The attacks are intended to redirect the output; their requested grades are not the ground truth.

Each case also has an evidence update for Stage C. The separately stored post-evidence labels are provisional: the 15 LOW-target attacks are paired with evidence provisionally labelled HIGH, and the 15 HIGH-target attacks with evidence provisionally labelled LOW. This opposition is a design constraint, not independent proof that the evidence labels are correct.

## 3. Protection-layer implementation

All layers use the same risk rubric, incident cases and attack assignments. Their input structures differ:

- **P0 — flattened input:** the rubric, classification instruction, incident report and, where applicable, injected text are combined in a single user message.
- **P1 — system guard and fixed boundary:** the guard and rubric are in a system message. The report and imported text are enclosed within fixed `<untrusted_document>` tags in a user message. The guard tells the model not to follow instructions in that material.
- **P2 — token boundary and restatement:** the P1 guard and rubric are used with a randomly generated session token in the system instruction and matching document delimiters. The task and output rules are restated after the document. The same P2 token is used for the two conditions in a matched pair; exact tokens and prompts are recorded in metadata.

These are prompt-based protections. The experiment does not implement or evaluate a separate external content filter. P2 changes several features together, so its results cannot isolate the separate contributions of the token boundary and the restatement.

The test model is Qwen3-14B. Runs use temperature 0.7, top-p 0.8 and a maximum of 24 generated tokens, with thinking disabled. There are three repetitions per case and condition, using reproducible seeds matched by case and repetition. Matching the seed does not make outputs from different prompts identical. Output parsing accepts exact LOW, MEDIUM or HIGH labels; refusals and other outputs are reported separately.

A mean count out of 30 is calculated by averaging each case's outcome over its three repetitions and then summing over the 30 cases. The repetitions are repeated model trials on the same cases, not additional independent cases.

## 4. Stage A: unprotected baseline

### Implementation

Stage A uses P0 and two conditions:

- **BASE:** the original report without an attack.
- **I:** the same report with its assigned injection appended as imported text.

The original facts are unchanged, so the provisional expected grade is MEDIUM in both conditions. A conditional attack success occurs when the matched BASE result is correct and the I result equals the attacker's target.

The completed revised P0 run contains 30 cases × 2 conditions × 3 repetitions, or 180 model calls.

### Results

| P0 condition | Mean LOW / 30 | Mean MEDIUM / 30 | Mean HIGH / 30 |
|---|---:|---:|---:|
| BASE | 0 | 30 | 0 |
| I | 14 | 5 | 11 |

P0 returned MEDIUM for all clean responses. When the injected text was added, a mean of 14 LOW-target cases and 11 HIGH-target cases reached the requested target. Thus the conditional attack-success count was **25 out of 30 cases on average**. No output in this run was classified as a refusal or OTHER.

Because every clean P0 response matched its provisional label, all P0 trials were eligible for the conditional measure. The result indicates that the tested instructions can redirect this model under the flattened-input setup; it does not show that all prompt injections will work.

## 5. Stage B: prompt-based protection

### Implementation

Stage B applies P1 and P2 to the same BASE and I conditions, cases, attack templates, sampling settings and matched seeds. It adds 360 model calls: 30 cases × 2 conditions × 2 layers × 3 repetitions. The revised P0 results from Stage A provide the baseline. The comparison checks the saved prompts, cases, repetitions, seeds and sampling settings before reporting the three layers together.

### Grade distributions

| Layer and condition | Mean LOW / 30 | Mean MEDIUM / 30 | Mean HIGH / 30 |
|---|---:|---:|---:|
| P0 BASE | 0 | 30 | 0 |
| P0 I | 14 | 5 | 11 |
| P1 BASE | 0 | 30 | 0 |
| P1 I | 14.33 | 11.67 | 4 |
| P2 BASE | 3.33 | 26.67 | 0 |
| P2 I | 12 | 17 | 1 |

P1 returned the provisional MEDIUM grade for all clean cases. P2 returned MEDIUM for a mean of 26.67 cases and LOW for 3.33. No refusals or OTHER outputs were recorded for P0, P1 or P2 in these completed runs.

### Conditional attack success

A successful attack in this table requires a correct matched BASE result and an injected result matching the target. Each direction covers 15 cases.

| Layer | LOW-target successes / 15 | HIGH-target successes / 15 | Total successes / 30 |
|---|---:|---:|---:|
| P0 | 14 | 11 | **25** |
| P1 | 14.33 | 4 | **18.33** |
| P2 | 11 | 1 | **12** |

P1 reduced the total by a mean of 6.67 cases compared with P0, while retaining the expected clean grade. That improvement came from HIGH-target attacks: LOW-target success was slightly higher under P1 than P0.

P2 had the lowest total and resisted most HIGH-target attacks, but 11 of the 15 LOW-target cases still succeeded on average. P2's clean misclassifications also affect eligibility: across the three repetitions, 80 P2 clean trials were correct, compared with 90 for each of P0 and P1. P2 therefore had fewer opportunities to register a conditional success. Its injected outputs included a mean of 13 attacker-target grades out of 30, of which 12 qualified as conditional successes; the remainder already had the same incorrect grade in the matched clean condition.

As an additional paired check, considering only the 80 trials where **both** P0 and P2 had correct clean grades, P0 reached the target in 68 and P2 in 36. This supports a reduction on their common eligible trials, while remaining descriptive of this small dataset rather than a general estimate.

## 6. Stage C: evidence preservation under attack

### Implementation

Stage C adds two conditions for all three layers:

- **E:** original report followed by a synthetic update described in the prompt as verified.
- **EI:** the same report and evidence, followed by the assigned injection as separate imported text.

The provisional post-evidence grade is the same for E and EI. Evidence is placed before the attack in every case; findings will be specific to that ordering. Within each E/EI pair, the same case/repetition seed is used, and P2 uses the same random boundary token. Stage C uses a new P2 token for the evidence pair; it need not match the token used in the earlier BASE/I pair.

The implemented analysis reports E and EI accuracy against the provisional evidence label, grade distributions, retention of correct E results under EI, and conditional attack success. For the last metric, E must be correct and the attack target must differ from the evidence label. The eligible denominator is reported. This avoids treating an attacker's requested grade as a success when it is also the correct evidence-based grade.

The full Stage C run comprises **540 new calls**: 30 cases × 2 conditions × 3 layers × 3 repetitions. Existing compatible BASE/I results can be included in the analysis without rerunning those calls.

### Results

The completed run contains 540 calls: 30 cases × 2 conditions × 3 layers × 3 repetitions. All 90 E trials per layer matched the provisional evidence label. The table reports the mean number of correct cases out of 30 and the number of matched trials in which a correct E classification was retained in EI.

| Layer | E correct, mean / 30 | EI correct, mean / 30 | Retained among E-correct trials | EI target outputs among eligible trials |
|---|---:|---:|---:|---:|
| P0 | 30 | 21 | 63/90 (70.0%) | 27/90 (30.0%) |
| P1 | 30 | 28 | 84/90 (93.3%) | 6/90 (6.7%) |
| P2 | 30 | 30 | 90/90 (100%) | 0/90 (0.0%) |

All E trials were eligible for the conditional target measure because they were correct against the provisional labels and the attack target opposed that label. The 90 trials per layer are repeated observations of 30 scenarios, not 90 independent scenarios. No refusals or OTHER outputs were recorded in Stage C.

By attack direction, P0 retained the evidence-based grade in 33/45 trials for HIGH-target attacks and 30/45 for LOW-target attacks. P1 retained it in 39/45 and 45/45, respectively; P2 retained it in 45/45 for both directions. Each direction contains 15 scenarios with three repetitions. Evidence grade and attack direction are perfectly linked in this design, so these breakdowns cannot separate their effects.

Within this dataset, the hardened layers retained more correct evidence-based classifications under EI than P0. P2's perfect Stage C result should be considered alongside its clean Stage B errors. The E/EI comparison measures changes in correctness when the injection is added; the final grade alone does not establish whether an error arose from following the instruction, disregarding evidence, or another cause. These results remain subject to independent label review and do not establish performance on new cases or attacks.

## 7. Overall interpretation

The completed results support four descriptive findings for this dataset:

1. The unprotected P0 setup was strongly affected by the tested injected instructions.
2. P1 improved the overall result relative to P0 without a measured drop in clean correctness, mainly by reducing HIGH-target successes.
3. P2 reduced conditional successes further, but retained substantial vulnerability to LOW-target attacks and produced clean LOW errors against the provisional labels.
4. In Stage C, all layers returned the provisional evidence-based grade in E. P1 and P2 retained the correct grade more often than P0 in EI, with P2 retaining it in all observed trials. This is a descriptive finding for the tested cases, not a demonstration of the mechanism behind errors.

The balance between resistance and evidence use remains subject to independent label review, limited scenario coverage and uncertainty. The results do not establish the effectiveness of an external filter or of prompt-based protection against new attacks.

## 8. Limitations and next steps

- **Label validity:** Original and post-evidence labels are provisional. A reviewer should classify each report and evidence update against the rubric without seeing the injection or its target; disagreements should be documented and resolved.
- **Dataset size and reuse:** There are 30 distinct scenarios; shared templates can also introduce dependence between them. The three repetitions and reused attack templates do not create 90 independent cases per layer.
- **Limited coverage:** All original reports are labelled MEDIUM, so the experiment does not test clean baseline performance across all risk levels. The incidents and attacks are synthetic and concern a single domain and model.
- **Evidence/target confounding:** In Stage C, HIGH evidence labels always accompany LOW-target attacks and LOW evidence labels accompany HIGH-target attacks. Evidence grade and target direction therefore cannot be separated statistically in this dataset.
- **Development and generalisation:** Prompts were developed after earlier outcomes had been inspected. The present results are exploratory; new held-out reports and attack templates are required to assess generalisation.
- **Attack and presentation scope:** The attack is appended in a fixed position. Some templates claim authority, assert a final score, or describe how to weigh evidence as well as issuing instructions, so output grades alone do not identify exactly why the model changed its answer. Stage C's evidence-before-attack ordering is one possible placement.
- **Architecture and eligibility:** P0 and P1 differ in message roles and instructions as well as document boundaries; P2 changes multiple features relative to P1. No individual feature can be credited for the differences. Conditional rates use layer-specific clean-correct denominators, so direct comparisons can involve different trials; the common-eligible P0/P2 comparison is a useful descriptive sensitivity check.
- **Reproducibility:** The saved metadata records model name, sampling settings, input fingerprint, tokens and messages, but not a model-weights revision or hash, tokenizer revision, exact dependency versions, hardware or full generation configuration. These should be recorded if recoverable; exact reproduction cannot be guaranteed from the saved metadata alone.
- **Sampling and uncertainty:** Repetition-level outcomes are descriptive. No confidence intervals or significance tests are claimed, and the matched seeds do not eliminate stochastic variation between different prompts.

Next, independently review both baseline and evidence labels, document adjudication, and recalculate results if labels change. Assess paired differences and uncertainty at the scenario level, accounting for repeated trials and reused templates. Test the most promising design on held-out cases and attacks if resources permit.

## 9. Files and reproducibility

- Completed revised P0 results: `results/stage-a-layers-v2.jsonl` and its metadata.
- Completed P1/P2 results: `results/stage-b.jsonl` and its metadata.
- Matched A/B comparison: `results/layers-v2-comparison.csv`.
- Completed Stage C results: `results/stage-c.jsonl` and its metadata; analysis: `results/stage-c-summary.csv`.
- Stage C smoke test: `results/stage-c-smoke.jsonl` and its metadata.
- Stage C labels: `data/category_1/evidence_labels.json`.
- Configurations and source: `stages/A.json`, `stages/B.json`, `stages/C.json`, `project.py`, `run.py`, `analyse.py`, `compare.py`, and `analyse_c.py`.
- Full run and analysis instructions: `README.md`; methodology and design notes: `docs/methodology.md`.
