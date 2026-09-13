"""
make_guide.py — ShadowMem Comprehensive Defense Master Guide
Generates an extensive, professional HTML document formatted specifically
for printing/saving cleanly as a multi-page PDF.
"""

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShadowMem - Complete Defense & Viva Master Guide</title>
<style>
  @page {
    size: A4;
    margin: 14mm 14mm 14mm 14mm;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    line-height: 1.45;
    font-size: 9.5pt;
  }
  h1 {
    color: #0f172a;
    font-size: 17pt;
    margin: 0 0 2px 0;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 4px;
  }
  .subtitle {
    color: #0284c7;
    font-weight: 600;
    font-size: 10pt;
    margin-bottom: 12px;
  }
  h2 {
    color: #0f172a;
    font-size: 11.5pt;
    margin-top: 14px;
    margin-bottom: 6px;
    border-left: 4px solid #0284c7;
    padding-left: 6px;
    background: #f8fafc;
    padding-top: 2px;
    padding-bottom: 2px;
  }
  h3 {
    color: #0369a1;
    font-size: 10pt;
    margin-top: 8px;
    margin-bottom: 3px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 6px;
    margin-bottom: 10px;
    font-size: 8.5pt;
  }
  th, td {
    border: 1px solid #cbd5e1;
    padding: 4px 6px;
    text-align: left;
    vertical-align: top;
  }
  th {
    background-color: #0f172a;
    color: white;
    font-weight: 600;
  }
  tr:nth-child(even) {
    background-color: #f8fafc;
  }
  .script-box {
    background-color: #f1f5f9;
    border-left: 3px solid #64748b;
    padding: 5px 8px;
    font-style: italic;
    margin-bottom: 5px;
    font-size: 8.5pt;
    color: #1e293b;
  }
  .term {
    font-weight: bold;
    color: #0f172a;
  }
  .qa-block {
    margin-bottom: 7px;
    page-break-inside: avoid;
  }
  .qa-q {
    font-weight: bold;
    color: #0f172a;
    font-size: 9pt;
  }
  .qa-a {
    color: #334155;
    margin-left: 6px;
    font-size: 8.5pt;
  }
  .formula-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    padding: 4px 8px;
    font-family: Consolas, monospace;
    font-size: 8.5pt;
    margin: 4px 0;
  }
  .page-break {
    page-break-before: always;
  }
</style>
</head>
<body>

<h1>ShadowMem: In-Memory Cyber Defense &amp; Forensics</h1>
<div class="subtitle">Complete Presentation Playbook, OS Internals, ML Math &amp; Technical Viva Defense Guide</div>

<h2>1. 15-Minute Team Allocation Strategy</h2>
<table>
  <tr><th>Speaker</th><th>Assigned Slides</th><th>Topic Focus</th><th>Target Time</th></tr>
  <tr><td><b>Speaker 1</b></td><td>Slides 1 &ndash; 3</td><td>Title, Executive Summary, Problem Identification (RAM vs Disk)</td><td>0:00 &ndash; 3:00 (3 min)</td></tr>
  <tr><td><b>Speaker 2</b></td><td>Slides 4 &ndash; 5</td><td>Literature Review, Research Gap &amp; Triage Bottlenecks</td><td>3:00 &ndash; 5:30 (2.5 min)</td></tr>
  <tr><td><b>Speaker 3</b></td><td>Slides 6 &ndash; 7</td><td>Original Contributions, System Architecture &amp; 5-Stage Forensics Loop</td><td>5:30 &ndash; 8:30 (3 min)</td></tr>
  <tr><td><b>Speaker 4</b></td><td>Slides 8 &ndash; 9</td><td>Low-Level OS Internals, 7-Vector Features &amp; ML Classification Pipeline</td><td>8:30 &ndash; 11:30 (3 min)</td></tr>
  <tr><td><b>Speaker 5</b></td><td>Slides 10 &ndash; 12</td><td>Implementation Tech Stack, Empirical Benchmarks &amp; Future Scope</td><td>11:30 &ndash; 14:30 (3 min)</td></tr>
</table>

<h2>2. Low-Level Windows OS Internals &amp; Forensic Mechanics</h2>
<ul>
  <li><span class="term">Virtual Address Descriptor (VAD) Trees:</span> Windows kernel memory manager maintains an internal AVL balanced binary search tree tracking all allocated virtual memory pages per process. Each node defines protection masks (NoAccess, ReadOnly, ReadWrite, ExecuteRead, or PAGE_EXECUTE_READWRITE). ShadowMem inspects these descriptor nodes out-of-band via VirtualQueryEx.</li>
  <li><span class="term">Unbacked RWX Memory:</span> Legitimate compiled binaries enforce Write XOR Execute (W^X). Dynamic shellcode, Cobalt Strike stagers, and reflective loaders allocate private anonymous memory with PAGE_EXECUTE_READWRITE permissions without a backing on-disk executable file.</li>
  <li><span class="term">Reflective DLL Injection:</span> Bypasses the standard NT loader (ntdll!LdrLoadDll) by writing an entire DLL directly into allocated RAM. A custom in-memory reflective loader resolves imports and base relocations manually. ShadowMem identifies unlinked PE headers (MZ 0x5A4D and PE\0\0 0x00004550) sitting inside private heap space.</li>
  <li><span class="term">Thread Start Address Discrepancies:</span> Legitimate execution threads originate within the bounds of a mapped module (e.g., ntdll.dll!RtlUserThreadStart). Injected execution threads (created via CreateRemoteThread or APC queuing) originate inside unbacked dynamic RWX buffers.</li>
</ul>

<h2>3. The 7-Vector Forensic Feature Matrix</h2>
<table>
  <tr><th>Feature Vector</th><th>Type</th><th>Forensic Purpose &amp; Description</th><th>Normal Range</th><th>Injected Range</th></tr>
  <tr><td><b>1. rwx_count</b></td><td>Integer</td><td>Total count of committed memory regions with PAGE_EXECUTE_READWRITE rights.</td><td>0 (or low if JIT)</td><td>&ge; 1 (typically private)</td></tr>
  <tr><td><b>2. unbacked_exec_count</b></td><td>Integer</td><td>Count of executable blocks (RX, RWX) without an associated on-disk image file.</td><td>0 (or static JIT heap)</td><td>High (&ge; 1 to dozens)</td></tr>
  <tr><td><b>3. total_rwx_bytes</b></td><td>Integer</td><td>Cumulative memory volume allocated across all RWX blocks.</td><td>0 KB</td><td>64 KB &ndash; 10+ MB</td></tr>
  <tr><td><b>4. num_threads</b></td><td>Integer</td><td>Active execution threads within the target process context.</td><td>1 &ndash; 60</td><td>Abnormal spikes</td></tr>
  <tr><td><b>5. thread_unbacked_start</b></td><td>Binary</td><td>Flags if any thread's initial execution pointer starts in unbacked RAM.</td><td>0</td><td>1</td></tr>
  <tr><td><b>6. is_known_jit_parent</b></td><td>Binary</td><td>Allowlist filter for known legitimate JIT engines (chrome.exe, node.exe, code.exe).</td><td>1 (for browsers)</td><td>0 (for LOLBins)</td></tr>
  <tr><td><b>7. vad_protection_anomaly</b></td><td>Binary</td><td>Detects dynamic protection state transitions (e.g., RW to RWX via VirtualProtect).</td><td>0</td><td>1</td></tr>
</table>

<h2>4. Machine Learning Mathematics: Class Imbalance &amp; SMOTE</h2>
<p>In standard enterprise environments, benign allocations represent 99.99% of memory pages. A baseline classifier trained on raw telemetry suffers from extreme class imbalance, defaulting to predicting "Benign".</p>
<p>ShadowMem applies <b>SMOTE (Synthetic Minority Over-sampling Technique)</b> to balance training vectors:</p>
<div class="formula-box">
  1. Measure Euclidean distance between minority feature vectors: d(x_i, x_j) = &radic;(&sum; (x_ik - x_jk)&sup2;)<br>
  2. Synthesize new minority feature points: x_new = x_i + &lambda; * (x_j - x_i), where &lambda; &isin; [0, 1]
</div>
<p>This balances the decision boundaries of our Random Forest / Gradient Boosting pipeline without duplicating identical records, yielding sub-millisecond inference latency (&lt; 1 ms) per process.</p>

<div class="page-break"></div>

<h2>5. Slide-by-Slide Delivery Scripts (15-Minute Defense)</h2>

<h3>Speaker 1 (Slides 1 &ndash; 3): Threat Landscape &amp; Problem Definition</h3>
<p><b>Slide 1 &mdash; Title:</b></p>
<div class="script-box">"Good morning, respected faculty and panel members. We are presenting ShadowMem: In-Memory Cyber Defense &amp; Forensics. Our system introduces an automated framework for real-time volatile memory forensics and fileless threat classification."</div>
<p><b>Slide 2 &mdash; Executive Summary:</b></p>
<div class="script-box">"Traditional antivirus checks static SHA-256 hashes on physical disks. Modern fileless malware operates entirely in volatile RAM, bypassing disk inspection completely. ShadowMem audits Windows kernel structures like the VAD tree and classifies active processes using machine learning with sub-second latency and under 2% CPU footprint."</div>
<p><b>Slide 3 &mdash; Problem Identification:</b></p>
<div class="script-box">"File-resident threats leave persistent storage footprints. In contrast, fileless threats execute inside legitimate Windows LOLBins like PowerShell or rundll32. When the machine restarts, volatile evidence disappears. Defending against modern adversaries requires continuous runtime memory forensics."</div>

<h3>Speaker 2 (Slides 4 &ndash; 5): Literature Review &amp; The Research Gap</h3>
<p><b>Slide 4 &mdash; Literature Review:</b></p>
<div class="script-box">"We evaluated three current defense paradigms: Static AV has zero visibility into memory-resident code. Post-mortem forensics (Volatility, Rekall) provide deep VAD visibility, but require multi-gigabyte RAM dumps that take hours. Behavioral EDRs cause high CPU overhead and remain vulnerable to API unhooking and Direct Kernel Object Manipulation."</div>
<p><b>Slide 5 &mdash; Research Gap:</b></p>
<div class="script-box">"This highlights three critical bottlenecks: forensic latency, operational overhead from full memory imaging, and false positives from naive RWX alerts. ShadowMem resolves this gap by combining targeted process-level triage with a supervised 7-feature ML pipeline."</div>

<h3>Speaker 3 (Slides 6 &ndash; 7): Innovations &amp; Pipeline Architecture</h3>
<p><b>Slide 6 &mdash; Novelty &amp; Original Contributions:</b></p>
<div class="script-box">"ShadowMem introduces four key contributions: targeted virtual address space triage instead of full physical RAM dumping; low-level kernel parsing of VAD nodes and PEBs; automated memory artifact carving; and a supervised forensic ML classifier that eliminates false positive cascades."</div>
<p><b>Slide 7 &mdash; System Architecture:</b></p>
<div class="script-box">"Our pipeline operates in five phases within an 850ms cycle: Interception monitors allocations; Acquisition snapshots targeted virtual memory; Forensics extracts VAD protections and thread pointers; ML evaluates the 7-feature vector; and Containment triggers automated process isolation."</div>

<h3>Speaker 4 (Slides 8 &ndash; 9): Feature Engineering &amp; ML Pipeline</h3>
<p><b>Slide 8 &mdash; Forensic Feature Analysis:</b></p>
<div class="script-box">"We examine four key memory threat signatures: unbacked RWX allocations used for staging shellcode, reflective DLL injection via unlinked PE headers, anomalous thread start addresses pointing outside mapped module memory, and PEB process tree discrepancies."</div>
<p><b>Slide 9 &mdash; Machine Learning Pipeline:</b></p>
<div class="script-box">"These observations are mapped into a 7-dimensional tabular vector. We resolve class imbalance using SMOTE over-sampling. The classifier executes in sub-millisecond inference time and is calibrated with JIT-aware rules to eliminate false alarms on core OS services."</div>

<h3>Speaker 5 (Slides 10 &ndash; 12): Implementation, Benchmarks &amp; Roadmap</h3>
<p><b>Slide 10 &mdash; Implementation &amp; Tech Stack:</b></p>
<div class="script-box">"Our implementation uses Python 3 with ctypes and pywin32 calling native Windows primitives like VirtualQueryEx and OpenProcess. ML is built with Scikit-learn and XGBoost. The system was validated against shellcode in an isolated Windows Enterprise sandbox."</div>
<p><b>Slide 11 &mdash; Performance Benchmarks:</b></p>
<div class="script-box">"Our benchmarks demonstrate: over 97.4% detection accuracy on shellcode and reflective injections, triage latency under 850 milliseconds, and less than 2.0% CPU overhead, validating continuous endpoint execution."</div>
<p><b>Slide 12 &mdash; Conclusion &amp; Future Scope:</b></p>
<div class="script-box">"ShadowMem demonstrates that memory forensics can transition from offline analysis into active runtime defense. Our future roadmap includes: Phase 1 Linux eBPF support, Phase 2 a Windows Kernel Driver (WDM) for zero-latency trapping, and Phase 3 deep learning on carved memory streams. Thank you."</div>

<div class="page-break"></div>

<h2>6. Anticipated Faculty Viva Cross-Examination (Q&amp;A)</h2>

<div class="qa-block">
  <div class="qa-q">Q1: Why use Machine Learning? Why not just write 'if memory == RWX: alert()'?</div>
  <div class="qa-a"><b>Ans:</b> Modern Just-In-Time (JIT) engines in browsers (Chrome, Edge) and Electron apps (VS Code) allocate unbacked RWX memory dynamically to compile JavaScript. A static rule creates dozens of false alarms per hour. Our ML model correlates allocation sizes, thread origins, and binary parentage to distinguish safe JIT execution from malicious payloads.</div>
</div>

<div class="qa-block">
  <div class="qa-q">Q2: If an attacker flips permissions from RWX to RX using VirtualProtect, does ShadowMem miss it?</div>
  <div class="qa-a"><b>Ans:</b> No. Feature 2 (unbacked_exec_count) tracks all executable memory pages (both RX and RWX) lacking an on-disk binary backing. Furthermore, Feature 7 flags the dynamic protection transition anomaly itself.</div>
</div>

<div class="qa-block">
  <div class="qa-q">Q3: What is the difference between VirtualAlloc and VirtualQueryEx?</div>
  <div class="qa-a"><b>Ans:</b> Both are native Win32 APIs in kernel32.dll. VirtualAlloc allocates, commits, or alters memory protections in a process. VirtualQueryEx is an inspection API: given a process handle and base address, it queries a MEMORY_BASIC_INFORMATION structure detailing allocation state (MEM_COMMIT) and protection flags (PAGE_EXECUTE_READWRITE).</div>
</div>

<div class="qa-block">
  <div class="qa-q">Q4: How does ShadowMem avoid the overhead of standard Volatility memory dumps?</div>
  <div class="qa-a"><b>Ans:</b> Traditional forensic tools dump complete physical RAM (16&ndash;32 GB) to disk, causing high I/O stalls. ShadowMem selectively reads only target user-mode process address spaces sequentially in RAM without freezing the machine or writing multi-gigabyte dump files.</div>
</div>

<div class="qa-block">
  <div class="qa-q">Q5: How does ShadowMem overcome User-Mode API hooking evasion?</div>
  <div class="qa-a"><b>Ans:</b> Many EDRs place hooks in user-mode ntdll.dll, which malware can bypass using direct syscalls. ShadowMem does not rely on passive inline hooks; it reads the registered VAD descriptors directly from kernel memory management structures via VirtualQueryEx.</div>
</div>

<div class="qa-block">
  <div class="qa-q">Q6: What privileges are required to run ShadowMem?</div>
  <div class="qa-a"><b>Ans:</b> ShadowMem requires Administrator privileges (SeDebugPrivilege). Calling OpenProcess with PROCESS_QUERY_INFORMATION and PROCESS_VM_READ permissions across isolated system processes requires administrative rights.</div>
</div>

<h2>7. Step-by-Step Live Defense Demonstration Sequence</h2>
<ol>
  <li><b>Baseline Scan:</b> Open http://127.0.0.1:8000 and run a scan. Point out that legitimate browser and IDE processes are classified as "Nominal" or "Legitimate JIT".</li>
  <li><b>Simulate Fileless Injection:</b> Open a terminal split and run <code>python test_injector.py</code>. Highlight that no file is dropped to disk; it allocates unbacked RWX memory directly in RAM.</li>
  <li><b>Detect Runtime Intrusion:</b> Re-scan the dashboard. Show the panel that the test process is immediately flagged with a 99%+ threat score and classified as "MALICIOUS".</li>
  <li><b>Inspect Forensic Dossier:</b> Click "Inspect" to open the modal dossier. Point out the RWX page count, unbacked allocations, and the automated SOC mitigation alert.</li>
  <li><b>Clean Teardown:</b> Stop the test injector using Ctrl + C to trigger VirtualFree. Re-scan the dashboard to show the threat cleared from the live telemetry radar.</li>
</ol>

</body>
</html>
"""

with open("presentation_guide.html", "w", encoding="utf-8") as f:
    f.write(html_content)

print("[✓] Updated presentation_guide.html with complete master guide!")