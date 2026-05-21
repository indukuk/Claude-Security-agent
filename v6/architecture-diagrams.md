# V6 Architecture Diagrams

## Complete Pipeline — 7 Layers with Parallelism

```mermaid
flowchart TB
    REPO[Target Repository<br/>Python + CDK + Frontend]
    
    subgraph "LAYER 0: DETERMINISTIC FOUNDATION [$0 • 26s]"
        direction TB
        
        subgraph "Parallel Track 1: Code"
            CPG[Enhanced CPG<br/>10.5K nodes<br/>Inter-procedural DFG]
            SEM[Semgrep<br/>4 rule sets<br/>121 findings]
            EW[Evidence Walker<br/>BFS source→sink]
            ABS[Absence Detector<br/>Must-guard specs]
            DIFF[Differential<br/>Guard-set compare]
        end
        
        subgraph "Parallel Track 2: Infra + Zero Trust"
            CDK[CDK/CFN Parser]
            Z3[Z3 IAM Proofs<br/>LeadingKeys<br/>Wildcards<br/>Deny effect]
            ZT[Zero Trust<br/>Blast radius<br/>Containment<br/>Network isolation]
            LAT[Lateral Movement<br/>Graph<br/>71 paths]
        end
        
        subgraph "Parallel Track 3: Frontend"
            FSEM[Frontend Semgrep<br/>XSS + innerHTML]
            SEC[Secret Detection<br/>API keys in JS]
        end
        
        CHAIN[Chain Synthesizer<br/>Precondition/Postcondition<br/>Composition Graph]
        EP[EVIDENCE PACKAGE<br/>All Layer 0 outputs bundled]
    end
    
    REPO --> CPG & CDK & FSEM
    CPG --> SEM --> EW
    CPG --> ABS & DIFF
    CDK --> Z3 --> ZT --> LAT
    EW & ABS & DIFF & LAT & SEC --> CHAIN --> EP

    subgraph "LAYER 1: LLM DISCOVERY [$10-15 • 5min parallel]"
        direction TB
        
        subgraph "Track A: Novel Patterns [Sonnet]"
            NP1[Declared-but-unenforced]
            NP2[Data flow to external svc]
            NP3[Implicit contract violations]
            NP4[Attack surface expansion]
            NP5[Temporal/state issues]
        end
        
        subgraph "Track B: Zero-Day [Opus]"
            ZD1[CVE Variant Analysis]
            ZD2[Spec Inference → Z3 Proof]
            ZD3[Anomaly Exploration]
            ZD4[AI/LLM Attack Vectors]
            ZD5[Cross-Language Transfer]
            ZD6[Commit-Diff Seeding]
        end
        
        subgraph "Track C: Investigation [Sonnet]"
            INV1[Tenant Isolation Expert]
            INV2[Auth Architecture Expert]
            INV3[Data Flow Expert]
            INV4[Infra Blast Radius Expert]
            INV5[Business Logic Expert]
        end
        
        MERGE[Merge + Deduplicate<br/>All findings by root cause]
    end
    
    EP --> NP1 & ZD1 & INV1
    NP5 & ZD6 & INV5 --> MERGE

    subgraph "LAYER 2: CoT SYNTHESIS [$3-5 • 2min parallel]"
        COT[7-Step Protocol × N findings<br/>Entry → Flow → Control →<br/>Cross-ref → Exploit →<br/>Confidence → Severity]
    end
    
    MERGE --> COT

    subgraph "LAYER 3: VALIDATION [$5-8 • 3min parallel]"
        direction LR
        DEB[Adversarial Debate<br/>Prosecutor → Defender → Judge<br/>Citation-required]
        ZTC[Zero Trust Cross-Ref<br/>Amplify or contain?<br/>Severity adjustment]
        ZDV[Zero-Day Validator<br/>Extra scrutiny<br/>Prove + reproduce]
    end
    
    COT --> DEB & ZTC & ZDV

    subgraph "LAYER 4: PROOF [$3-5 • 2min parallel]"
        direction LR
        EXP[Exploit Generator<br/>Executable PoC<br/>curl / Python]
        FIX[Fix Generator<br/>+ Re-scan Verify<br/>Loop ×3]
        REG[Regression Test<br/>Generator<br/>pytest per finding]
    end
    
    DEB & ZTC & ZDV --> EXP & FIX & REG

    subgraph "LAYER 5: SYNTHESIS [$2-3 • 2min]"
        NAR[Narrative Synthesis<br/>Principal Consultant<br/>Themed report +<br/>Zero Trust section +<br/>Zero-Day section +<br/>Attack chains]
    end
    
    EXP & FIX & REG --> NAR

    subgraph "LAYER 6: LEARNING [$1 • 1min]"
        FB[Feedback Loop<br/>Novel → Semgrep rules<br/>Zero-day → Absence specs<br/>Variants → Chain capabilities<br/>Written to rules/discovered/]
    end
    
    NAR --> FB
    FB -.->|"Next scan"| CPG

    style CPG fill:#adf,stroke:#333
    style Z3 fill:#fda,stroke:#333
    style ZT fill:#fda,stroke:#333
    style ZD1 fill:#f66,stroke:#333,color:#fff
    style ZD2 fill:#f66,stroke:#333,color:#fff
    style ZD3 fill:#f66,stroke:#333,color:#fff
    style ZD4 fill:#f66,stroke:#333,color:#fff
    style ZD5 fill:#f66,stroke:#333,color:#fff
    style ZD6 fill:#f66,stroke:#333,color:#fff
    style NP1 fill:#f9e,stroke:#333
    style NP2 fill:#f9e,stroke:#333
    style NP3 fill:#f9e,stroke:#333
    style NP4 fill:#f9e,stroke:#333
    style NP5 fill:#f9e,stroke:#333
    style INV1 fill:#fcf,stroke:#333
    style INV2 fill:#fcf,stroke:#333
    style INV3 fill:#fcf,stroke:#333
    style INV4 fill:#fcf,stroke:#333
    style INV5 fill:#fcf,stroke:#333
    style DEB fill:#fcc,stroke:#333
    style NAR fill:#cff,stroke:#333
    style FB fill:#cfc,stroke:#333
    style EP fill:#ff9,stroke:#333
```

## Layer 0: Parallel Deterministic Execution

```mermaid
gantt
    title Layer 0 Parallel Execution (26s total)
    dateFormat ss
    axisFormat %S s

    section Code Track
    CPG Build (tree-sitter)           :cpg, 00, 3s
    Semgrep (4 rule sets)             :sem, after cpg, 12s
    Evidence Walks                     :ew, after sem, 1s
    Absence Detector                   :abs, after sem, 1s
    Differential Analyzer              :diff, after sem, 1s

    section Infra Track
    CDK Parse                          :cdk, 00, 1s
    Z3 IAM Proofs (30 findings)        :z3, after cdk, 5s
    Zero Trust Analyzer                :zt, after z3, 2s
    Lateral Movement Graph             :lat, after zt, 1s

    section Frontend Track
    Semgrep Frontend Rules             :fsem, 00, 3s
    Secret Detection                   :sec, after fsem, 1s

    section Synthesis
    Chain Synthesizer                  :chain, after diff, 1s
    Evidence Package Assembly          :ep, after chain, 1s
```

## Layer 1: Three Parallel LLM Discovery Tracks

```mermaid
flowchart LR
    EP[Evidence<br/>Package]
    
    subgraph "Track A: Novel Patterns"
        direction TB
        A_SYS["System: 'Find what rules miss'<br/>Exclusion: Phase 0 findings"]
        A1["① Declared-but-unenforced<br/>'required_permission' in metadata<br/>but never checked in code"]
        A2["② Data flow to external services<br/>Tokens → Bedrock session<br/>PII → CloudWatch logs"]
        A3["③ Implicit contract violations<br/>80% do X, 20% don't<br/>The 20% are bugs"]
        A4["④ Attack surface expansion<br/>Reachable when shouldn't be<br/>Returns more than needed"]
        A5["⑤ Temporal/state issues<br/>TOCTOU, stale sessions<br/>Token reuse"]
        A_SYS --> A1 --> A2 --> A3 --> A4 --> A5
    end
    
    subgraph "Track B: Zero-Day"
        direction TB
        B_SYS["System: 'Find genuinely novel vulns'<br/>Model: Opus (frontier required)"]
        B1["① CVE Variant Analysis<br/>Known CVE as seed →<br/>Find structural analog"]
        B2["② Spec Inference + Z3<br/>Infer invariant →<br/>Prove violation (SAT)"]
        B3["③ Anomaly Exploration<br/>Code that 'feels wrong'<br/>Different trust assumptions"]
        B4["④ AI/LLM Attack Vectors<br/>Memory leakage<br/>Prompt chains<br/>Agent control"]
        B5["⑤ Cross-Language Transfer<br/>Python vuln →<br/>JS/CDK equivalent?"]
        B6["⑥ Commit-Diff Seeding<br/>Recent fix →<br/>Find unfixed siblings"]
        B_SYS --> B1 --> B2 --> B3 --> B4 --> B5 --> B6
    end
    
    subgraph "Track C: Investigation"
        direction TB
        C_SYS["System: 'Deep domain analysis'<br/>5 parallel experts"]
        C1[Tenant Isolation]
        C2[Auth Architecture]
        C3[Data Flow]
        C4[Infra Blast Radius]
        C5[Business Logic]
        C_SYS --> C1 & C2 & C3 & C4 & C5
    end
    
    EP --> A_SYS & B_SYS & C_SYS

    style B_SYS fill:#f66,stroke:#333,color:#fff
    style B1 fill:#f66,stroke:#333,color:#fff
    style B2 fill:#f66,stroke:#333,color:#fff
    style B3 fill:#f66,stroke:#333,color:#fff
    style B4 fill:#f66,stroke:#333,color:#fff
    style B5 fill:#f66,stroke:#333,color:#fff
    style B6 fill:#f66,stroke:#333,color:#fff
    style A_SYS fill:#f9e,stroke:#333
    style C_SYS fill:#fcf,stroke:#333
```

## Track B: Zero-Day Discovery — Detail

```mermaid
flowchart TB
    subgraph "Inputs"
        EP[Evidence Package]
        CVE[v3/knowledge/<br/>CVE Database<br/>Breach cases<br/>Exploit payloads]
        GIT[Git History<br/>Recent commits<br/>Security fixes]
        SRC[Full Source Code<br/>All handlers +<br/>infra + frontend]
    end

    subgraph "Zero-Day Agent (Opus)"
        direction TB
        
        S1["Strategy 1: CVE Variant Analysis<br/><br/>Load known vuln examples as seeds.<br/>'Find structurally similar code<br/>that isn't an exact match.'<br/><br/>Big Sleep technique:<br/>40% of 0-days are variants"]
        
        S2["Strategy 2: Specification Inference + Z3<br/><br/>LLM infers: 'This value must always be<br/>tenant-scoped'<br/>Z3 checks: 'Is there a path where it ISN'T?'<br/>SAT → novel finding with formal proof"]
        
        S3["Strategy 3: Anomaly-Driven Exploration<br/><br/>'Which functions handle errors differently?'<br/>'Which paths have different trust assumptions?'<br/>'What assumptions could be WRONG?'"]
        
        S4["Strategy 4: AI/LLM-Specific Vectors<br/><br/>• Bedrock memory sharing (cross-tenant leak)<br/>• Prompt injection via stored data<br/>• Agent loop control via user input<br/>• Tool use escalation (trick AI → danger)"]
        
        S5["Strategy 5: Cross-Language Transfer<br/><br/>'This Python vuln — does the JS<br/>frontend have an equivalent?'<br/>'Does CDK rely on app-layer security<br/>that doesn't exist?'"]
        
        S6["Strategy 6: Commit-Diff Seeding<br/><br/>'This commit fixed a bug.<br/>Find other places where the<br/>SAME class exists unfixed.'"]
    end

    subgraph "Output"
        ZDC[Zero-Day Candidates]
        SPEC[Inferred Specifications<br/>+ Z3 Proofs]
        VAR[Variant Instances]
        RULES[Rule Suggestions<br/>for Layer 6]
    end

    EP & CVE & GIT & SRC --> S1
    S1 --> S2 --> S3 --> S4 --> S5 --> S6
    S6 --> ZDC & SPEC & VAR & RULES

    style S1 fill:#f66,stroke:#333,color:#fff
    style S2 fill:#f66,stroke:#333,color:#fff
    style S3 fill:#f66,stroke:#333,color:#fff
    style S4 fill:#f66,stroke:#333,color:#fff
    style S5 fill:#f66,stroke:#333,color:#fff
    style S6 fill:#f66,stroke:#333,color:#fff
```

## Layer 3: Validation — Three Parallel Validators

```mermaid
flowchart TB
    FIND[Confirmed Finding<br/>from Layer 2 CoT]
    
    subgraph "Validator 1: Adversarial Debate"
        direction TB
        BUNDLE["Evidence Bundle [immutable]<br/>[1] CPG taint path<br/>[2] Z3 proof<br/>[3] Source code<br/>[4] Infra config<br/>[5] Secure contrast<br/>[6] CoT reasoning<br/>[7] Blast radius"]
        PROS["PROSECUTOR<br/>'This IS exploitable'<br/>Must cite [N]"]
        DEF["DEFENDER<br/>'This is mitigated'<br/>Must cite [N]<br/>Cannot invent mitigations"]
        JUDGE["JUDGE<br/>Discard uncited claims<br/>Z3 proofs > code > inference<br/><br/>Verdict:<br/>CONFIRMED /<br/>CONFIRMED_ADJUSTED /<br/>DISMISSED"]
        BUNDLE --> PROS --> DEF --> JUDGE
    end
    
    subgraph "Validator 2: Zero Trust Cross-Reference"
        direction TB
        ZTC1["Look up resource's<br/>blast radius"]
        ZTC2{"Is resource<br/>UNCONTAINED?"}
        ZTC3["AMPLIFY severity<br/>'If exploited, attacker<br/>gains access to ALL<br/>tenant data'"]
        ZTC4["Note containment<br/>'Impact limited by<br/>scoped IAM'"]
        ZTC1 --> ZTC2
        ZTC2 -->|Yes + Internet-facing| ZTC3
        ZTC2 -->|No| ZTC4
    end
    
    subgraph "Validator 3: Zero-Day Extra Scrutiny"
        direction TB
        ZDV1["Is this truly novel?<br/>Check CVE/CWE databases"]
        ZDV2["Can we PROVE it?<br/>Z3 / code path / test"]
        ZDV3["Does it survive<br/>adversarial challenge?"]
        ZDV4{"All 3 pass?"}
        ZDV5[CONFIRMED<br/>as Zero-Day]
        ZDV6[Downgrade to<br/>Novel Pattern]
        ZDV1 --> ZDV2 --> ZDV3 --> ZDV4
        ZDV4 -->|Yes| ZDV5
        ZDV4 -->|No| ZDV6
    end
    
    FIND --> BUNDLE & ZTC1 & ZDV1

    style PROS fill:#fcc,stroke:#333
    style DEF fill:#cfc,stroke:#333
    style JUDGE fill:#ccf,stroke:#333
    style ZTC3 fill:#f66,stroke:#333,color:#fff
    style ZDV5 fill:#f66,stroke:#333,color:#fff
```

## Layer 6: Self-Improving Feedback Loop

```mermaid
flowchart TB
    subgraph "Input: Confirmed Novel/Zero-Day Findings"
        NF[Novel Pattern<br/>Findings]
        ZDF[Zero-Day<br/>Findings]
        VF[Variant<br/>Findings]
    end

    subgraph "Rule Generator"
        direction TB
        RG1["Analyze finding structure"]
        RG2{"What type of<br/>deterministic rule<br/>can catch this?"}
        
        SEM_R["Generate Semgrep Rule<br/><br/>rules:<br/>  - id: discovered-xyz<br/>    pattern: ...<br/>    message: ...<br/>    severity: ERROR"]
        
        ABS_R["Generate Absence Spec<br/><br/>MustGuard(<br/>  sink_pattern=...,<br/>  guard_pattern=...,<br/>  guard_type=...,<br/>)"]
        
        CHAIN_R["Generate Chain Capability<br/><br/>CAPABILITY_MAP[category] = (<br/>  preconditions,<br/>  postconditions,<br/>)"]
        
        SPEC_R["Generate Z3 Specification<br/><br/>Property: 'value X must<br/>never reach service Y<br/>without redaction'"]
    end

    subgraph "Output: New Rules"
        direction TB
        DISC["v6/rules/discovered/<br/>new_semgrep_rules.yaml"]
        LEARN["v6/specs/learned/<br/>new_must_guards.py"]
        CAPS["v6/specs/learned/<br/>new_capabilities.py"]
        Z3S["v6/specs/learned/<br/>new_z3_properties.py"]
    end

    subgraph "Validation"
        VAL1["Apply rule to<br/>compliance repo"]
        VAL2{"Fires on the<br/>original finding?"}
        VAL3{"False positives<br/>on clean code?"}
        VAL4[Rule ACCEPTED<br/>Added to Layer 0]
        VAL5[Rule REJECTED<br/>Needs tuning]
    end

    NF & ZDF & VF --> RG1 --> RG2
    RG2 -->|"data flow pattern"| SEM_R
    RG2 -->|"missing control"| ABS_R
    RG2 -->|"composition"| CHAIN_R
    RG2 -->|"provable property"| SPEC_R
    
    SEM_R & ABS_R & CHAIN_R & SPEC_R --> DISC & LEARN & CAPS & Z3S
    
    DISC --> VAL1 --> VAL2
    VAL2 -->|Yes| VAL3
    VAL2 -->|No| VAL5
    VAL3 -->|No FPs| VAL4
    VAL3 -->|Has FPs| VAL5

    style ZDF fill:#f66,stroke:#333,color:#fff
    style VAL4 fill:#cfc,stroke:#333
    style VAL5 fill:#fcc,stroke:#333
```

## The Flywheel: Scanner Gets Smarter Over Time

```mermaid
flowchart LR
    subgraph "Scan 1"
        S1_L0["Layer 0<br/>15 known"]
        S1_L1["Layer 1<br/>+2 novel<br/>+1 zero-day"]
        S1_L6["Layer 6<br/>3 new rules"]
        S1_L0 --> S1_L1 --> S1_L6
    end
    
    subgraph "Scan 2"
        S2_L0["Layer 0<br/>18 known<br/>(+3 from rules)"]
        S2_L1["Layer 1<br/>+1 novel"]
        S2_L6["Layer 6<br/>1 new rule"]
        S2_L0 --> S2_L1 --> S2_L6
    end
    
    subgraph "Scan 3"
        S3_L0["Layer 0<br/>19 known"]
        S3_L1["Layer 1<br/>+0 novel"]
        S3_L6["Layer 6<br/>Skip"]
        S3_L0 --> S3_L1 --> S3_L6
    end
    
    subgraph "Scan N (CI/CD)"
        SN_L0["Layer 0 ONLY<br/>19 known<br/>$0 • 26s"]
    end
    
    S1_L6 -->|"rules added"| S2_L0
    S2_L6 -->|"rules added"| S3_L0
    S3_L6 -->|"nothing new"| SN_L0

    style S1_L1 fill:#f9e,stroke:#333
    style S2_L1 fill:#f9e,stroke:#333
    style S3_L1 fill:#efe,stroke:#333
    style SN_L0 fill:#cfc,stroke:#333
```

## Cost Optimization: Model Selection Per Component

```mermaid
flowchart TB
    subgraph "Opus (frontier required)"
        direction LR
        O1[Track B:<br/>Zero-Day Discovery<br/>~$5-8]
    end
    
    subgraph "Sonnet (cost-effective)"
        direction LR
        S1[Track A:<br/>Novel Patterns<br/>~$2-3]
        S2[Track C:<br/>Investigation ×5<br/>~$3-5]
        S3[Layer 2:<br/>CoT ×15<br/>~$2-3]
        S4[Layer 3:<br/>Debate ×8<br/>~$3-5]
        S5[Layer 4:<br/>Exploit+Fix ×12<br/>~$2-3]
        S6[Layer 5:<br/>Narrator<br/>~$2-3]
    end
    
    subgraph "No LLM"
        direction LR
        N1[Layer 0:<br/>Deterministic<br/>$0]
        N2[Layer 6:<br/>Rule validation<br/>$0]
    end

    style O1 fill:#f66,stroke:#333,color:#fff
    style S1 fill:#f9e,stroke:#333
    style S2 fill:#f9e,stroke:#333
    style S3 fill:#f9e,stroke:#333
    style S4 fill:#f9e,stroke:#333
    style S5 fill:#f9e,stroke:#333
    style S6 fill:#f9e,stroke:#333
    style N1 fill:#adf,stroke:#333
    style N2 fill:#adf,stroke:#333
```

## Zero Trust: Assume-Breach Blast Radius Map

```mermaid
flowchart TB
    subgraph "Internet (Attacker)"
        ATK[Attacker]
    end

    subgraph "UNCONTAINED (50% blast radius each)"
        direction LR
        OBS["role_observer_fn<br/>AUTH: none<br/>───────────<br/>logs:* (all groups)<br/>DynamoDB RW<br/>S3 Read<br/>Bedrock invoke"]
        V2["role_v2_fn<br/>AUTH: none<br/>───────────<br/>bedrock-agentcore:*<br/>DynamoDB RW<br/>S3 RWD<br/>Lambda invoke"]
        V3["role_v3_fn<br/>AUTH: none<br/>───────────<br/>bedrock-agentcore:*<br/>DynamoDB RW<br/>S3 RWD<br/>Lambda invoke"]
        AGT["role_agent_fn<br/>AUTH: none<br/>───────────<br/>bedrock-agentcore:*<br/>DynamoDB RW<br/>S3 RWD<br/>textract:*"]
        AGT2["role_agent_fn_v2<br/>AUTH: none<br/>───────────<br/>bedrock-agentcore:*<br/>DynamoDB RW<br/>S3 RWD<br/>Lambda invoke"]
    end

    subgraph "Data Stores (ALL TENANTS)"
        DDB[(DynamoDB<br/>Sessions Table<br/>No LeadingKeys<br/>──────────<br/>Evaluations<br/>Evidence hashes<br/>Conversations)]
        S3[(S3 Bucket<br/>Evidence Files<br/>All tenants<br/>──────────<br/>Uploaded docs<br/>Compliance proofs)]
        CW[(CloudWatch<br/>All Log Groups<br/>──────────<br/>Request bodies<br/>Session IDs<br/>Tenant IDs)]
    end

    subgraph "AI Services"
        BED[Bedrock<br/>agentcore:*<br/>──────────<br/>Create/delete agents<br/>Invoke any model<br/>Access any memory]
    end

    subgraph "CONTAINED (internal, auth=authorizer)"
        AUTH["role_auth_handler_fn<br/>Cognito admin<br/>3 tables RW"]
        DATA["role_data_fn<br/>Tenants table<br/>S3 PutObject"]
        USER["role_user_mgmt_fn<br/>Cognito admin<br/>2 tables RW"]
    end

    ATK -->|"No auth required"| OBS & V2 & V3 & AGT & AGT2
    OBS --> CW & DDB & S3
    V2 --> DDB & S3 & BED
    V3 --> DDB & S3 & BED
    AGT --> DDB & S3 & BED
    AGT2 --> DDB & S3 & BED
    
    DDB -.->|"shared_data<br/>lateral"| AUTH & DATA
    S3 -.->|"shared_data<br/>lateral"| DATA

    style OBS fill:#f66,stroke:#333,color:#fff
    style V2 fill:#f66,stroke:#333,color:#fff
    style V3 fill:#f66,stroke:#333,color:#fff
    style AGT fill:#f66,stroke:#333,color:#fff
    style AGT2 fill:#f66,stroke:#333,color:#fff
    style DDB fill:#fc9,stroke:#333
    style S3 fill:#fc9,stroke:#333
    style CW fill:#fc9,stroke:#333
    style BED fill:#fc9,stroke:#333
    style AUTH fill:#cfc,stroke:#333
    style DATA fill:#cfc,stroke:#333
    style USER fill:#cfc,stroke:#333
```

## Prompt Engineering Process Per Agent

```mermaid
flowchart TB
    subgraph "Phase 0: Research"
        R1[Study Big Sleep prompts]
        R2[Study Buttercup architecture]
        R3[Study Semgrep Assistant]
        R4[Prompt engineering literature<br/>ReAct, ToT, Self-Consistency]
        R1 & R2 & R3 & R4 --> PLAYBOOK[Prompt Engineering<br/>Playbook]
    end

    subgraph "Phase 1: Design 3 Variants"
        VA["Variant A<br/>(e.g., heavy persona<br/>+ CVE few-shots)"]
        VB["Variant B<br/>(e.g., minimal persona<br/>+ spec inference)"]
        VC["Variant C<br/>(e.g., anomaly-first<br/>+ cross-reference)"]
    end

    subgraph "Phase 2: Test Against Compliance Repo"
        TA["Run Variant A<br/>→ findings"]
        TB["Run Variant B<br/>→ findings"]
        TC["Run Variant C<br/>→ findings"]
    end

    subgraph "Phase 3: Measure"
        M1[Coverage<br/>findings count]
        M2[Precision<br/>false positive rate]
        M3[Grounding<br/>citation quality]
        M4[Novelty<br/>unique discoveries]
        M5[Cost<br/>token usage]
    end

    subgraph "Phase 4: Select Winner"
        WIN[Best variant<br/>becomes production<br/>prompt]
        DOC[Document WHY<br/>it won]
    end

    PLAYBOOK --> VA & VB & VC
    VA --> TA
    VB --> TB
    VC --> TC
    TA & TB & TC --> M1 & M2 & M3 & M4 & M5
    M1 & M2 & M3 & M4 & M5 --> WIN & DOC

    style WIN fill:#cfc,stroke:#333
    style PLAYBOOK fill:#ff9,stroke:#333
```

## V6 vs AWS Security Agent vs Pure LLM — Final Comparison

```mermaid
flowchart TB
    subgraph "AWS Security Agent"
        direction TB
        SA1[Preflight]
        SA2[Static Analysis<br/>AI agents read code]
        SA3[Finalize]
        SA1 --> SA2 --> SA3
        SA_OUT["15 Findings<br/>47-page PDF<br/>~$50-100<br/>~10min<br/>───────────<br/>✓ Deep narrative<br/>✓ Evidence walks<br/>✗ No formal proofs<br/>✗ No zero trust<br/>✗ No zero-day<br/>✗ No attack chains<br/>✗ No fix verification"]
    end

    subgraph "Pure LLM (2-step CoT)"
        direction TB
        PL1[Step 1: Mental model]
        PL2[Step 2: Scan]
        PL1 --> PL2
        PL_OUT["15 Findings + 2 novel<br/>~$2.50<br/>~5min<br/>───────────<br/>✓ Deep narrative<br/>✓ Concrete exploits<br/>✓ Novel discoveries<br/>✗ No formal proofs<br/>✗ No zero trust<br/>✗ Non-reproducible<br/>✗ May miss findings"]
    end

    subgraph "V6 Hybrid"
        direction TB
        V6_L0["Layer 0: Deterministic<br/>+ Zero Trust"]
        V6_L1["Layer 1: Discovery<br/>(Novel + Zero-Day + Investigate)"]
        V6_L2["Layers 2-4: Validate<br/>+ Prove + Fix"]
        V6_L5["Layers 5-6: Report<br/>+ Learn"]
        V6_L0 --> V6_L1 --> V6_L2 --> V6_L5
        V6_OUT["15+ Findings + novel + zero-day<br/>Zero trust assessment<br/>Formal Z3 proofs<br/>~$15-20<br/>~15min<br/>───────────<br/>✓ Deep narrative<br/>✓ Formal proofs<br/>✓ Zero trust<br/>✓ Zero-day discovery<br/>✓ Attack chains<br/>✓ Verified fixes<br/>✓ Regression tests<br/>✓ Self-improving<br/>✓ 100% reproducible (L0)"]
    end

    SA3 --> SA_OUT
    PL2 --> PL_OUT
    V6_L5 --> V6_OUT

    style SA_OUT fill:#fec,stroke:#333
    style PL_OUT fill:#fec,stroke:#333
    style V6_OUT fill:#cfc,stroke:#333
    style V6_L0 fill:#adf,stroke:#333
    style V6_L1 fill:#f9e,stroke:#333
```

## Legend

```mermaid
flowchart LR
    D["Deterministic<br/>(no LLM, $0)"]
    F["Formal Methods<br/>(Z3 proofs)"]
    S["Sonnet<br/>(cost-effective)"]
    O["Opus<br/>(frontier, zero-day)"]
    V["Validation<br/>(debate/prove)"]
    L["Learning<br/>(feedback loop)"]
    
    style D fill:#adf,stroke:#333
    style F fill:#fda,stroke:#333
    style S fill:#f9e,stroke:#333
    style O fill:#f66,stroke:#333,color:#fff
    style V fill:#ccf,stroke:#333
    style L fill:#cfc,stroke:#333
```

| Color | Meaning |
|-------|---------|
| Blue | Deterministic computation — no LLM, $0, reproducible |
| Orange | Formal methods — Z3 SMT solver, mathematical proofs |
| Pink | LLM (Sonnet) — cost-effective reasoning |
| Red | LLM (Opus) — frontier model for zero-day discovery |
| Purple | Validation — debate, cross-reference, extra scrutiny |
| Green | Learning / output — feedback loop, final report |
| Yellow | Evidence package — shared data between layers |
