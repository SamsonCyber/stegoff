"""
ApprovalLens -- Human-in-the-Loop trap detector.

Defends against Trap Category 6 (Franklin et al., 2026): attacks that target
human supervisors rather than agents. Tactics include approval fatigue,
dense summaries hiding malicious actions, and phishing links disguised
as legitimate recommendations.

Usage:
    from stegoff.detectors.approval_lens import review_agent_output

    result = review_agent_output(
        agent_output="Here's what I'll do: ...",
        proposed_actions=["send_email", "delete_file"],
        task_description="Summarize the quarterly report",
    )
    if result.risk_level == "high":
        # Force detailed human review
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from stegoff.report import Finding, Severity, StegMethod


@dataclass
class ReviewResult:
    """Result of analyzing agent output for human-in-the-loop traps."""
    risk_level: str  # "low", "medium", "high"
    risk_score: float  # 0.0-1.0
    findings: list[Finding] = field(default_factory=list)
    action_mismatches: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)
    complexity_score: float = 0.0
    fatigue_warning: bool = False
    summary: str = ""


# Actions that should rarely appear together
_CONFLICTING_ACTIONS = {
    ("read_file", "delete_file"),
    ("summarize", "send_email"),
    ("search", "write_file"),
    ("analyze", "execute_code"),
}

# High-risk action verbs in agent prose
_ACTION_VERBS = re.compile(
    r'\b(?:delet|remov|drop|send|email|transfer|upload|post|publish|'
    r'execut|deploy|push|install|grant|revok|modif|overwrit)\w*\b',
    re.IGNORECASE,
)

# URL pattern
_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)

# Domain shorteners and suspicious TLDs
_SUSPICIOUS_DOMAINS = re.compile(
    r'(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|'
    r'rb\.gy|cutt\.ly|shorturl|tiny\.cc|'
    r'[a-z0-9-]+\.(?:tk|ml|ga|cf|gq|xyz|top|click|link|info|buzz))\b',
    re.IGNORECASE,
)

# Technical jargon density indicators
_JARGON_RE = re.compile(
    r'\b(?:idempoten|ephemeral|deterministic|orthogonal|mutex|semaphore|'
    r'heurist|polynomial|asymptot|eigenvalue|gradient|backpropagat|'
    r'serializ|deserializ|marshalling|daemon|syscall|ioctl|'
    r'kubernetes|terraform|istio|envoy|cilium)\w*\b',
    re.IGNORECASE,
)


def review_agent_output(
    agent_output: str,
    proposed_actions: list[str] | None = None,
    task_description: str = "",
    approval_count_this_session: int = 0,
    session_duration_minutes: float = 0.0,
) -> ReviewResult:
    """
    Analyze agent output before presenting to a human for approval.

    Detects patterns designed to exploit human oversight weaknesses:
    approval fatigue, complexity camouflage, action hiding, and
    phishing link injection.

    Args:
        agent_output: The text the agent wants to show the human.
        proposed_actions: Tool names the agent wants to execute.
        task_description: What the agent was originally asked to do.
        approval_count_this_session: How many approvals the human has given.
        session_duration_minutes: How long the session has been running.
    """
    result = ReviewResult(risk_level="low", risk_score=0.0)
    findings = []

    # 1. Approval fatigue detection
    fatigue_findings = _detect_approval_fatigue(
        approval_count_this_session, session_duration_minutes
    )
    findings.extend(fatigue_findings)
    if fatigue_findings:
        result.fatigue_warning = True

    # 2. Complexity camouflage
    complexity, complexity_findings = _detect_complexity_camouflage(
        agent_output, task_description
    )
    result.complexity_score = complexity
    findings.extend(complexity_findings)

    # 3. Action-task mismatch
    if proposed_actions:
        mismatch_findings, mismatches = _detect_action_mismatch(
            proposed_actions, task_description, agent_output
        )
        findings.extend(mismatch_findings)
        result.action_mismatches = mismatches

    # 4. Hidden actions in prose
    prose_findings = _detect_hidden_actions(agent_output, proposed_actions or [])
    findings.extend(prose_findings)

    # 5. Suspicious URLs
    url_findings, sus_urls = _detect_suspicious_urls(agent_output, task_description)
    findings.extend(url_findings)
    result.suspicious_urls = sus_urls

    # 6. Minimization language
    mini_findings = _detect_minimization(agent_output)
    findings.extend(mini_findings)

    # Aggregate risk score
    score = 0.0
    for f in findings:
        weight = {
            Severity.CRITICAL: 0.4,
            Severity.HIGH: 0.25,
            Severity.MEDIUM: 0.15,
            Severity.LOW: 0.05,
        }.get(f.severity, 0.1)
        score += weight
    score = min(score, 1.0)

    result.risk_score = score
    result.findings = findings
    result.risk_level = (
        "high" if score >= 0.6
        else "medium" if score >= 0.3
        else "low"
    )
    result.summary = _build_summary(result)
    return result


def _detect_approval_fatigue(
    approval_count: int, duration_minutes: float
) -> list[Finding]:
    """Flag when a human is likely fatigued from rapid approvals."""
    findings = []

    if approval_count >= 10 and duration_minutes > 0:
        rate = approval_count / max(duration_minutes, 1.0)
        if rate > 2.0:  # More than 2 approvals per minute
            findings.append(Finding(
                method=StegMethod.HUMAN_IN_LOOP_TRAP,
                severity=Severity.HIGH,
                confidence=min(0.5 + rate * 0.1, 0.95),
                description=(
                    f"Approval fatigue risk: {approval_count} approvals in "
                    f"{duration_minutes:.0f}min ({rate:.1f}/min)"
                ),
                evidence=f"rate={rate:.1f}/min, count={approval_count}",
                metadata={"detector": "approval_fatigue", "rate": rate},
            ))
    elif approval_count >= 20:
        findings.append(Finding(
            method=StegMethod.HUMAN_IN_LOOP_TRAP,
            severity=Severity.MEDIUM,
            confidence=0.7,
            description=f"High approval count: {approval_count} this session",
            evidence=f"count={approval_count}",
            metadata={"detector": "approval_fatigue"},
        ))

    return findings


def _detect_complexity_camouflage(
    output: str, task_description: str
) -> tuple[float, list[Finding]]:
    """Detect when agent output is suspiciously dense or technical relative to the task."""
    findings = []

    words = output.split()
    word_count = len(words)
    if word_count < 10:
        return 0.0, findings

    # Jargon density
    jargon_matches = _JARGON_RE.findall(output)
    jargon_density = len(jargon_matches) / word_count

    # Average word length (proxy for complexity)
    avg_word_len = sum(len(w) for w in words) / word_count

    # Sentence count and avg length
    sentences = re.split(r'[.!?]+', output)
    sentences = [s.strip() for s in sentences if s.strip()]
    avg_sentence_len = word_count / max(len(sentences), 1)

    # Complexity score: 0.0-1.0
    complexity = min(1.0, (
        jargon_density * 5.0 +
        max(0, avg_word_len - 5.0) * 0.2 +
        max(0, avg_sentence_len - 20.0) * 0.02
    ))

    # Compare to task description complexity
    task_words = task_description.split() if task_description else []
    task_jargon = len(_JARGON_RE.findall(task_description)) if task_description else 0

    if task_description and len(task_words) > 3:
        task_complexity = min(1.0, task_jargon / max(len(task_words), 1) * 5.0)
        gap = complexity - task_complexity

        if gap > 0.4:
            findings.append(Finding(
                method=StegMethod.HUMAN_IN_LOOP_TRAP,
                severity=Severity.MEDIUM,
                confidence=min(0.5 + gap, 0.9),
                description=(
                    f"Output complexity ({complexity:.2f}) significantly exceeds "
                    f"task complexity ({task_complexity:.2f})"
                ),
                evidence=f"jargon_density={jargon_density:.3f}, avg_sentence_len={avg_sentence_len:.0f}",
                metadata={
                    "detector": "complexity_camouflage",
                    "output_complexity": complexity,
                    "task_complexity": task_complexity,
                },
            ))

    if complexity > 0.7:
        findings.append(Finding(
            method=StegMethod.HUMAN_IN_LOOP_TRAP,
            severity=Severity.MEDIUM,
            confidence=0.6,
            description=f"Highly technical output (complexity={complexity:.2f}) may resist human review",
            evidence=f"jargon_count={len(jargon_matches)}, avg_word_len={avg_word_len:.1f}",
            metadata={"detector": "complexity_camouflage", "complexity": complexity},
        ))

    return complexity, findings


def _detect_action_mismatch(
    proposed_actions: list[str], task_description: str, output: str
) -> tuple[list[Finding], list[str]]:
    """Detect when proposed actions don't match the stated task."""
    findings = []
    mismatches = []

    task_lower = task_description.lower()

    # Check for high-risk actions on low-risk tasks
    read_task = any(w in task_lower for w in [
        "read", "summarize", "analyze", "review", "list", "show", "describe", "check"
    ])

    delete_actions = {"delete", "remove", "drop", "truncate", "rm", "destroy"}
    network_actions = {"send_email", "post", "upload", "publish", "push", "fetch", "curl"}
    exec_actions = {"execute", "run_code", "eval", "exec", "subprocess"}

    action_set = {a.lower() for a in proposed_actions}

    if read_task:
        for action in action_set:
            for dangerous_set, label in [
                (delete_actions, "destructive"),
                (network_actions, "network"),
                (exec_actions, "execution"),
            ]:
                if any(d in action for d in dangerous_set):
                    mismatches.append(f"{label} action '{action}' on read-only task")
                    findings.append(Finding(
                        method=StegMethod.HUMAN_IN_LOOP_TRAP,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        description=f"Action mismatch: {label} action on read-only task",
                        evidence=f"task='{task_description[:100]}', action='{action}'",
                        metadata={
                            "detector": "action_mismatch",
                            "action": action,
                            "mismatch_type": label,
                        },
                    ))

    # Check for conflicting action pairs
    for a1, a2 in _CONFLICTING_ACTIONS:
        has_a1 = any(a1 in a for a in action_set)
        has_a2 = any(a2 in a for a in action_set)
        if has_a1 and has_a2:
            mismatches.append(f"conflicting actions: {a1} + {a2}")
            findings.append(Finding(
                method=StegMethod.HUMAN_IN_LOOP_TRAP,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description=f"Conflicting action pair: {a1} + {a2}",
                evidence=f"actions={proposed_actions}",
                metadata={"detector": "action_mismatch", "conflict": [a1, a2]},
            ))

    return findings, mismatches


def _detect_hidden_actions(output: str, declared_actions: list[str]) -> list[Finding]:
    """Detect action verbs in prose that aren't in the declared action list."""
    findings = []
    declared_lower = " ".join(declared_actions).lower()

    matches = _ACTION_VERBS.findall(output)
    if not matches:
        return findings

    # Filter to actions mentioned in prose but not declared
    undeclared = []
    for match in matches:
        match_root = match.lower()[:6]
        if match_root not in declared_lower:
            undeclared.append(match)

    # Separate destructive verbs (always suspicious) from general verbs
    _DESTRUCTIVE_ROOTS = {"delet", "remov", "drop", "send", "email", "transfer",
                          "upload", "execut", "deploy", "push", "grant", "revok",
                          "overwrit", "install", "publish"}
    unique_undeclared = set(undeclared)
    destructive_undeclared = {v for v in unique_undeclared
                              if any(v.lower().startswith(r) for r in _DESTRUCTIVE_ROOTS)}

    # Flag if: 1+ destructive undeclared verbs, OR 3+ any undeclared verbs
    if destructive_undeclared or len(unique_undeclared) >= 3:
        severity = Severity.HIGH if destructive_undeclared else Severity.MEDIUM
        flagged = destructive_undeclared or unique_undeclared
        findings.append(Finding(
            method=StegMethod.HUMAN_IN_LOOP_TRAP,
            severity=severity,
            confidence=0.7 if destructive_undeclared else 0.6,
            description=(
                f"Agent prose mentions undeclared action verbs: "
                f"{', '.join(sorted(flagged)[:5])}"
            ),
            evidence=f"undeclared: {', '.join(sorted(unique_undeclared)[:10])}",
            metadata={
                "detector": "hidden_actions",
                "undeclared_verbs": sorted(unique_undeclared),
                "destructive_verbs": sorted(destructive_undeclared),
            },
        ))

    return findings


def _detect_suspicious_urls(
    output: str, task_description: str
) -> tuple[list[Finding], list[str]]:
    """Find URLs that don't match the task context or use suspicious domains."""
    findings = []
    suspicious = []

    urls = _URL_RE.findall(output)
    if not urls:
        return findings, suspicious

    # Extract task-relevant domains
    task_urls = _URL_RE.findall(task_description)
    task_domains = set()
    for u in task_urls:
        domain = _extract_domain(u)
        if domain:
            task_domains.add(domain)

    for url in urls:
        domain = _extract_domain(url)

        # Check shorteners / suspicious TLDs
        if _SUSPICIOUS_DOMAINS.search(url):
            suspicious.append(url)
            findings.append(Finding(
                method=StegMethod.HUMAN_IN_LOOP_TRAP,
                severity=Severity.HIGH,
                confidence=0.85,
                description=f"Suspicious URL domain in agent output: {domain}",
                evidence=f"url={url[:200]}",
                metadata={"detector": "suspicious_url", "domain": domain, "type": "shortener_or_suspicious_tld"},
            ))
        # Check domain mismatch with task
        elif task_domains and domain and domain not in task_domains:
            # Not necessarily malicious, but worth flagging
            suspicious.append(url)
            findings.append(Finding(
                method=StegMethod.HUMAN_IN_LOOP_TRAP,
                severity=Severity.LOW,
                confidence=0.5,
                description=f"URL domain '{domain}' not mentioned in task",
                evidence=f"url={url[:200]}, task_domains={task_domains}",
                metadata={"detector": "suspicious_url", "domain": domain, "type": "domain_mismatch"},
            ))

    return findings, suspicious


def _detect_minimization(output: str) -> list[Finding]:
    """Detect language that downplays the significance of proposed actions."""
    findings = []

    minimization_patterns = [
        (r'\bjust\s+(?:a\s+)?(?:quick|small|minor|tiny|simple)\b', "downplaying scope"),
        (r'\b(?:routine|standard|normal)\s+(?:procedure|operations?|update|maintenance|steps?|checks?)\b', "normalizing"),
        (r'\b(?:nothing\s+to\s+worry|perfectly\s+safe|no\s+risk|harmless)\b', "risk dismissal"),
        (r'\b(?:everyone\s+does\s+this|standard\s+practice|common\s+approach)\b', "social normalizing"),
        (r'\bdon\'?t\s+(?:need\s+to\s+)?(?:worry|review|check)\b', "discouraging review"),
        (r'\b(?:approve\s+to\s+continue|click\s+(?:yes|approve|allow))\b', "rushing approval"),
    ]

    matched_types = set()
    for pattern, ptype in minimization_patterns:
        if re.search(pattern, output, re.IGNORECASE) and ptype not in matched_types:
            matched_types.add(ptype)

    if len(matched_types) >= 2:
        findings.append(Finding(
            method=StegMethod.HUMAN_IN_LOOP_TRAP,
            severity=Severity.MEDIUM,
            confidence=0.7,
            description=f"Minimization language detected: {', '.join(sorted(matched_types))}",
            evidence=f"{len(matched_types)} minimization patterns",
            metadata={"detector": "minimization", "patterns": sorted(matched_types)},
        ))

    return findings


def _extract_domain(url: str) -> str | None:
    """Extract domain from URL."""
    match = re.match(r'https?://([^/:\s]+)', url)
    return match.group(1).lower() if match else None


def _build_summary(result: ReviewResult) -> str:
    """Build human-readable summary of review."""
    parts = [f"Risk: {result.risk_level} ({result.risk_score:.2f})"]
    if result.fatigue_warning:
        parts.append("FATIGUE WARNING: slow down and review carefully")
    if result.action_mismatches:
        parts.append(f"Action mismatches: {', '.join(result.action_mismatches[:3])}")
    if result.suspicious_urls:
        parts.append(f"Suspicious URLs: {len(result.suspicious_urls)}")
    if result.complexity_score > 0.5:
        parts.append(f"Output complexity: {result.complexity_score:.2f} (may resist review)")
    if result.findings:
        parts.append(f"Total findings: {len(result.findings)}")
    return " | ".join(parts)
