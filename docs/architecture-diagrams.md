# Architecture Diagrams (V1 → V5)

## V1: Agent Architecture with CPG + Deterministic Checks

```mermaid
flowchart TB
    subgraph Input
        REPO[Target Repository]
    end

    subgraph "V1 Pipeline"
        direction TB
        ORCH[Orchestrator<br/>scanner.py]
        
        subgraph "Python Analysis"
            CPG[CPG Builder<br/>regex + tree-sitter]
            TAINT[Taint Analyzer]
            SPEC[Spec Inference]
        end
        
        subgraph "Infrastructure Analysis"
            CFN[CFN Parser]
            DET[Deterministic Checks]
            IAM[IAM Analyzer]
            TOXIC[Toxic Combo Detector]
        end
        
        subgraph "Validation"
            VAL[Adversarial Validator<br/>LLM-powered]
        end
        
        LLM[Bedrock Claude<br/>Budget: $5]
        REPORT[Report JSON]
    end

    REPO --> ORCH
    ORCH --> CPG
    CPG --> TAINT
    TAINT --> SPEC
    ORCH --> CFN
    CFN --> DET
    DET --> IAM
    IAM --> TOXIC
    ORCH --> VAL
    VAL <--> LLM
    ORCH --> REPORT

    style LLM fill:#f9e,stroke:#333
    style REPORT fill:#9f9,stroke:#333
```

## V2: Semgrep Taint + Chain-of-Thought Reasoning

```mermaid
flowchart LR
    subgraph Input
        REPO[Target Repo]
    end

    subgraph "V2 Pipeline"
        direction LR
        subgraph "Semgrep Scanning"
            SR[Python Taint Rules]
            SG[Gap Coverage Rules]
            SF[Frontend XSS Rules]
        end
        
        subgraph "CoT Engine"
            COT[6-Step Chain-of-Thought<br/>Context Gathering]
        end
        
        subgraph "Correlation"
            COR[Cross-Boundary<br/>Compound Risk<br/>Detection]
        end
        
        RPT[Final Report]
    end

    REPO --> SR
    REPO --> SG
    REPO --> SF
    SR --> COT
    SG --> COT
    SF --> COT
    COT --> COR
    COR --> RPT

    style COT fill:#f9e,stroke:#333
    style RPT fill:#9f9,stroke:#333
```

## V3: Generator → Verifier → Prover (13 Agents)

```mermaid
flowchart TB
    subgraph Input
        REPO[Target Repo]
    end

    subgraph "Stage 1: GENERATOR — 9 Parallel Agents"
        direction LR
        S1[Semgrep Python]
        S2[Semgrep Gaps]
        S3[Semgrep Frontend]
        S4[Infra Checks]
        S5[Business Logic]
        S6[Spec Inference]
        S7[Community Rules]
        S8[Compound Scanner]
        S9[Rule Generator]
    end

    subgraph "Stage 2: VERIFIER — Grounded Debate"
        direction LR
        PROS[Prosecutor<br/>8K tokens]
        DEF[Defender<br/>8K tokens]
        JUDGE[Judge<br/>16K tokens]
    end

    subgraph "Stage 3: PROVER"
        direction LR
        EXP[Exploit Generator]
        FIX[Fix Generator]
        FVAL[Fix Validator<br/>re-scan]
    end

    subgraph "Harness"
        DAG[DAG Executor<br/>parallel]
        DUR[Durable Executor<br/>retry + checkpoint]
        STATE[State Store<br/>JSON persistence]
    end

    REPO --> S1 & S2 & S3 & S4 & S5 & S6 & S7
    S1 & S2 & S4 --> S8
    S1 & S2 --> S9
    
    S1 & S2 & S3 & S4 & S5 & S6 & S7 & S8 & S9 --> PROS
    PROS --> DEF
    DEF --> JUDGE
    
    JUDGE --> EXP
    EXP --> FIX
    FIX --> FVAL

    DAG -.-> S1 & S2 & S3 & S4 & S5 & S6 & S7
    DUR -.-> DAG
    STATE -.-> DUR

    style PROS fill:#f9e,stroke:#333
    style DEF fill:#f9e,stroke:#333
    style JUDGE fill:#f9e,stroke:#333
    style EXP fill:#f9e,stroke:#333
```

## V4: Deep Deterministic Analysis (No LLM)

```mermaid
flowchart TB
    subgraph Input
        REPO[Target Repo]
    end

    subgraph "Stage 1: Enhanced CPG"
        CPG[Enhanced CPG Builder<br/>10.5K nodes • 9.2K edges<br/>Inter-procedural DFG<br/>548 functions • 16 handlers]
    end

    subgraph "Stage 2: Multi-Scanner Detection"
        direction LR
        SEM[Semgrep<br/>119 findings]
        Z3[Z3 IAM Verification<br/>30 proven findings<br/>14 CRITICAL]
    end

    subgraph "Stage 3: Deep Analysis"
        direction LR
        EW[Evidence Walker<br/>BFS source→sink<br/>5-9 step traces]
        ABS[Absence Detector<br/>Must-guard specs<br/>Deviant behavior mining]
        DIFF[Differential Analyzer<br/>Guard-set comparison<br/>Bypass path detection]
    end

    subgraph "Stage 4: Composition"
        CHAIN[Chain Synthesizer<br/>Precondition/postcondition graph<br/>Composite severity escalation]
    end

    subgraph "Stage 5: Report"
        RPT[Report Generator<br/>Markdown + JSON<br/>Verified/unverified annotations]
    end

    REPO --> CPG
    CPG --> SEM & Z3
    SEM --> EW
    CPG --> ABS & DIFF
    EW & ABS & DIFF & Z3 --> CHAIN
    CHAIN --> RPT

    style CPG fill:#adf,stroke:#333
    style Z3 fill:#fda,stroke:#333
    style CHAIN fill:#daf,stroke:#333
    style RPT fill:#9f9,stroke:#333
```

## V5: Expert Security Code Reviewer (6-Layer Pipeline)

```mermaid
flowchart TB
    subgraph Input
        REPO[Target Repo<br/>Python + CDK]
    end

    subgraph "LAYER 0: Deterministic Evidence Collection"
        direction TB
        
        subgraph "0A: Code Analysis"
            CPG[Enhanced CPG<br/>10.5K nodes]
            SEM[Semgrep<br/>4 rule sets]
            EW[Evidence Walker<br/>20 walks]
            ABS[Absence Detector<br/>9 findings]
            DIFF[Differential<br/>10 bypass paths]
        end
        
        subgraph "0B: Infrastructure + Zero Trust"
            Z3[Z3 Zelkova<br/>30 IAM proofs]
            ZT[Zero Trust Analyzer]
            BR[Blast Radius<br/>5 uncontained]
            LAT[Lateral Movement<br/>71 paths]
        end
        
        subgraph "0C: Composition"
            CHAIN[Attack Chain<br/>Synthesizer<br/>10 CRITICAL chains]
        end
    end

    subgraph "LAYER 1: Deep Investigation Agents"
        direction LR
        A1[Tenant Isolation<br/>Expert]
        A2[Auth Architecture<br/>Expert]
        A3[Data Flow<br/>Expert]
        A4[Infra Blast Radius<br/>Expert]
        A5[Business Logic<br/>Expert]
    end

    subgraph "LAYER 2: Chain-of-Thought Synthesis"
        COT[7-Step Protocol<br/>per finding<br/>Entry → Flow → Control →<br/>Cross-ref → Exploit →<br/>Confidence → Severity]
    end

    subgraph "LAYER 3: Adversarial Grounded Debate"
        direction LR
        PROS[Prosecutor<br/>Argues exploitability]
        DEF2[Defender<br/>Argues safety]
        JUDGE2[Judge<br/>Citation scoring<br/>CONFIRMED / DISMISSED]
    end

    subgraph "LAYER 4: Exploit Proof + Fix Verification"
        direction LR
        EXPLOIT[Exploit Generator<br/>Executable curl/Python]
        FIXGEN[Fix Generator<br/>References secure patterns]
        FIXVER[Fix Verifier<br/>Re-scan loop ×3]
    end

    subgraph "LAYER 5: Narrative Synthesis"
        NAR[Senior Analyst Agent<br/>Writes final report<br/>Themed findings + chains +<br/>zero trust assessment]
    end

    subgraph Output
        FINAL[Final Report<br/>Markdown + JSON<br/>Exceeds AWS SA quality]
    end

    REPO --> CPG
    CPG --> SEM & EW & ABS & DIFF
    REPO --> Z3
    Z3 --> ZT
    ZT --> BR & LAT
    SEM & EW & ABS & DIFF & BR & LAT --> CHAIN

    CHAIN --> A1 & A2 & A3 & A4 & A5

    A1 & A2 & A3 & A4 & A5 --> COT

    COT --> PROS
    PROS --> DEF2
    DEF2 --> JUDGE2

    JUDGE2 --> EXPLOIT & FIXGEN
    FIXGEN --> FIXVER

    EXPLOIT & FIXVER & JUDGE2 --> NAR
    NAR --> FINAL

    style CPG fill:#adf,stroke:#333
    style Z3 fill:#fda,stroke:#333
    style ZT fill:#fda,stroke:#333
    style A1 fill:#f9e,stroke:#333
    style A2 fill:#f9e,stroke:#333
    style A3 fill:#f9e,stroke:#333
    style A4 fill:#f9e,stroke:#333
    style A5 fill:#f9e,stroke:#333
    style COT fill:#f9e,stroke:#333
    style PROS fill:#fcc,stroke:#333
    style DEF2 fill:#cfc,stroke:#333
    style JUDGE2 fill:#ccf,stroke:#333
    style NAR fill:#f9e,stroke:#333
    style FINAL fill:#9f9,stroke:#333
```

## V5 Zero Trust Detail: Assume-Breach Analysis

```mermaid
flowchart TB
    subgraph "Internet-Facing Resources (No Auth)"
        OBS[Observer Lambda<br/>auth=none<br/>UNCONTAINED]
        V2[V2 Lambda<br/>auth=none<br/>UNCONTAINED]
        V3[V3 Lambda<br/>auth=none<br/>UNCONTAINED]
        AGT[Agent Lambda<br/>auth=none<br/>UNCONTAINED]
        AGT2[Agent V2 Lambda<br/>auth=none<br/>UNCONTAINED]
    end

    subgraph "Data Stores (All Tenants)"
        DDB[(DynamoDB<br/>Sessions Table<br/>No LeadingKeys)]
        S3[(S3 Bucket<br/>Evidence Files<br/>All Tenants)]
        CW[(CloudWatch<br/>All Log Groups)]
    end

    subgraph "AI Services"
        BED[Bedrock<br/>agentcore:*]
    end

    subgraph "Internal Services (Authorizer)"
        AUTH[Auth Handler]
        DATA[Data Handler]
        USER[User Mgmt]
    end

    OBS -->|"logs:* on *"| CW
    OBS -->|"read_write_data"| DDB
    OBS -->|"grant_read"| S3
    OBS -->|"bedrock:InvokeModel"| BED

    V2 -->|"read_write_data"| DDB
    V2 -->|"GetObject,PutObject,Delete"| S3
    V2 -->|"bedrock-agentcore:*"| BED

    V3 -->|"read_write_data"| DDB
    V3 -->|"GetObject,PutObject,Delete"| S3
    V3 -->|"bedrock-agentcore:*"| BED

    AGT -->|"read_write_data"| DDB
    AGT -->|"GetObject,PutObject,Delete"| S3
    AGT -->|"bedrock-agentcore:*"| BED

    DDB -.->|"shared_data<br/>lateral movement"| AUTH
    DDB -.->|"shared_data"| DATA

    style OBS fill:#f66,stroke:#333,color:#fff
    style V2 fill:#f66,stroke:#333,color:#fff
    style V3 fill:#f66,stroke:#333,color:#fff
    style AGT fill:#f66,stroke:#333,color:#fff
    style AGT2 fill:#f66,stroke:#333,color:#fff
    style DDB fill:#fc9,stroke:#333
    style S3 fill:#fc9,stroke:#333
    style CW fill:#fc9,stroke:#333
    style BED fill:#fc9,stroke:#333
```

## Evolution Timeline

```mermaid
gantt
    title Security Scanner Evolution
    dateFormat  YYYY-MM-DD
    axisFormat  %b %d

    section V1
    CPG + Deterministic + LLM Validation     :v1, 2026-05-15, 2d

    section V2
    Semgrep Taint + CoT + Correlator         :v2, 2026-05-16, 1d

    section V3
    Generator→Verifier→Prover (13 agents)   :v3, 2026-05-17, 2d

    section V4
    Evidence Walks + Absence + Differential  :v4, 2026-05-19, 1d

    section V5
    Zero Trust + LLM Agents + Full Pipeline  :v5, 2026-05-20, 1d
```

## V5 Data Flow: Evidence Package Assembly

```mermaid
flowchart LR
    subgraph "Source Files"
        PY[77 Python files]
        CDK[CDK Stacks]
        JS[Frontend JS]
    end

    subgraph "Layer 0 Engines"
        CPG[Enhanced CPG<br/>10.5K nodes]
        SEM[Semgrep<br/>4 rule sets]
        Z3[Z3 Solver]
        ZT[Zero Trust]
    end

    subgraph "Evidence Package"
        direction TB
        EP[EvidencePackage]
        EP --- C1[CPG graph]
        EP --- C2[119 semgrep findings]
        EP --- C3[20 evidence walks]
        EP --- C4[9 absence findings]
        EP --- C5[10 differential findings]
        EP --- C6[30 Z3 proofs]
        EP --- C7[5 blast radii]
        EP --- C8[71 lateral paths]
        EP --- C9[10 attack chains]
        EP --- C10[Full source code]
    end

    subgraph "LLM Agents"
        L1[Layer 1: 5 Investigators]
        L2[Layer 2: CoT ×15]
        L3[Layer 3: Debate ×8]
        L4[Layer 4: Exploit ×11]
        L5[Layer 5: Narrator]
    end

    PY --> CPG --> EP
    CDK --> Z3 --> EP
    CDK --> ZT --> EP
    PY --> SEM --> EP
    JS --> SEM

    EP --> L1 --> L2 --> L3 --> L4 --> L5

    style EP fill:#adf,stroke:#333
    style L1 fill:#f9e,stroke:#333
    style L2 fill:#f9e,stroke:#333
    style L3 fill:#f9e,stroke:#333
    style L4 fill:#f9e,stroke:#333
    style L5 fill:#f9e,stroke:#333
```

## V5 vs AWS Security Agent: Architecture Comparison

```mermaid
flowchart TB
    subgraph "AWS Security Agent"
        direction TB
        SA1[Preflight<br/>Setup logging + env]
        SA2[Static Analysis<br/>AI agents read code]
        SA3[Finalize<br/>Validation + reporting]
        SA1 --> SA2 --> SA3
        
        SA_OUT[15 Findings<br/>47-page PDF<br/>Agent confidence]
    end

    subgraph "V5 Security Agent"
        direction TB
        V5_L0[Layer 0: Deterministic<br/>CPG + Semgrep + Z3 + Zero Trust<br/>26s • $0]
        V5_L1[Layer 1: Investigation<br/>5 domain expert agents<br/>tool use + extended thinking]
        V5_L2[Layer 2: CoT<br/>7-step protocol per finding]
        V5_L3[Layer 3: Debate<br/>Citation-required adversarial]
        V5_L4[Layer 4: Prove<br/>Exploits + verified fixes]
        V5_L5[Layer 5: Narrate<br/>Final report synthesis]
        V5_L0 --> V5_L1 --> V5_L2 --> V5_L3 --> V5_L4 --> V5_L5
        
        V5_OUT[43+ Findings<br/>Formal Z3 proofs<br/>Zero trust assessment<br/>Attack chains<br/>Verified fixes<br/>~$6 Opus / $1.20 Sonnet]
    end

    SA3 --> SA_OUT
    V5_L5 --> V5_OUT

    style SA2 fill:#f9e,stroke:#333
    style V5_L0 fill:#adf,stroke:#333
    style V5_L1 fill:#f9e,stroke:#333
    style V5_L2 fill:#f9e,stroke:#333
    style V5_L3 fill:#fcc,stroke:#333
    style V5_L4 fill:#dfd,stroke:#333
    style V5_L5 fill:#f9e,stroke:#333
    style V5_OUT fill:#9f9,stroke:#333
    style SA_OUT fill:#9f9,stroke:#333
```

## Legend

```mermaid
flowchart LR
    D[Deterministic<br/>No LLM] --- L[LLM-Powered<br/>Agent] --- F[Formal<br/>Z3 Proof] --- O[Output]
    
    style D fill:#adf,stroke:#333
    style L fill:#f9e,stroke:#333
    style F fill:#fda,stroke:#333
    style O fill:#9f9,stroke:#333
```

| Color | Meaning |
|-------|---------|
| Blue | Deterministic computation (CPG, graph algorithms) |
| Pink | LLM-powered agent (extended thinking, tool use) |
| Orange | Formal methods (Z3 SMT solver, mathematical proofs) |
| Red | Adversarial / attack (prosecutor, uncontained resources) |
| Green | Output / verified / safe |
