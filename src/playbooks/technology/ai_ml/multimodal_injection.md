---
id: technology.ai_ml.multimodal_injection
title: "LLM: Multimodal & File-Based Injection"
category: technology
vulnerabilityClass: multimodal_injection
appliesToStack: apps sending user-provided images/audio/documents to a model
requiresAnyTag: ["llm-api", "llm-app", "llm-agent"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM01:2025 Prompt Injection"
cweRefs:
  - "CWE-94"
  - "CWE-20"
realWorldReferences:
  - title: "Prompt injection via images — instructions hidden in image pixels/text that vision models obey"
    url: "https://embracethered.com/blog/posts/2023/vision-prompt-injection-hidden-text-in-images/"
    type: security_blog
  - title: "Injection through documents/PDFs/OCR ingested by multimodal assistants (indirect injection carriers)"
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    type: security_blog
  - title: "Adversarial and hidden-text image inputs steering vision-language models"
    url: "https://arxiv.org/abs/2307.10490"
    type: research_paper
quickModeSummary: >
  Multimodal models read instructions from images, audio, and documents, so
  every non-text input is a prompt-injection carrier — text hidden in an image
  (low-contrast, tiny, or in metadata), instructions embedded in a PDF/DOCX/SVG,
  or audio the model transcribes. This is indirect prompt injection through a
  channel developers rarely think to distrust. Check that user-provided
  images/audio/files sent to a model are treated as untrusted instruction
  carriers with the same handling as untrusted text (see prompt_injection):
  privilege separation from tools, no auto-egress rendering of the model's
  response, and awareness that content moderation on the visible text won't catch
  hidden-in-image instructions. Also validate file types/sizes and strip active
  content, and remember OCR/transcription turns file/audio content into model
  instructions.
fileSelectionHint:
  roles: ["service", "controller", "route_handler", "upload_handler", "agent"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core"]
  matchAuthMapTags: ["llm-api", "llm-app", "file-upload"]
  maxFiles: 10
  priorityOrder: ["upload_handler", "controller", "agent", "service"]
severityHeuristics:
  critical:
    - "User-provided images/audio/documents are sent to a multimodal model that also has tools/agency or auto-egress, so instructions hidden in the media drive tool calls or data exfiltration (indirect injection via a non-text channel)"
  high:
    - "User media is fed to a model whose output gates a security decision or is rendered in a way that can exfiltrate (markdown images/links), with no recognition that hidden-in-media instructions can steer it"
    - "OCR/transcription output (from an untrusted file/audio) is placed into the prompt as trusted context, so document/audio content becomes model instructions"
  medium:
    - "User media reaches a model but impact is limited to same-user text output with no tools/egress; still an injection surface, ranked by blast radius"
    - "Uploaded files sent to the model lack type/size validation or active-content stripping, enlarging the carrier surface"
  low:
    - "Media is processed by a model whose output is inert (validated/constrained, no tools, no egress) — residual only; confirm the output is constrained before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:llm_boundary"
  relatedNodeIds: ["component:input_validation", "component:external_system"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:llm_boundary"
    to: "component:input_validation"
  - relation: enables
    from: "component:llm_boundary"
    to: "component:external_system"
commonAiCodingMistakes:
  - "AI builds an 'upload an image and ask about it' or 'summarize this PDF' feature and treats the media as inert data, not realizing a vision/document model reads and obeys text hidden in the image or embedded in the document — indirect injection through a channel that bypasses text-based moderation."
  - "AI moderates or filters the user's typed text but not the uploaded media, so instructions hidden in an image (low-contrast, tiny font, EXIF/metadata) or in a document reach the model unfiltered."
  - "AI feeds OCR/transcription output straight into the prompt as trusted context, turning arbitrary document/audio content into model instructions."
  - "AI gives a multimodal assistant tools/agency AND accepts user media, so a poisoned image can drive tool calls (confused deputy via the vision channel)."
  - "AI accepts arbitrary uploaded file types (SVG, HTML, Office) to send to the model without validation/sanitization, broadening the injection and file-parsing surface."
falsePositiveGuardrails:
  - "Do not flag media processing whose model output is inert (constrained/validated, no tools, no egress rendering) beyond a same-user text answer — the injection surface exists but the blast radius is limited; rank accordingly."
  - "A multimodal pipeline that keeps media/OCR/transcription output as untrusted, delimited data and enforces privilege separation from tools/egress (per prompt_injection) has the correct architecture — the model being steerable by media is expected; the control is the boundary."
  - "File type/size validation and active-content stripping on uploads before they reach the model reduce the carrier surface — factor these in."
  - "Cross-reference prompt_injection (the general boundary) and file_uploads (upload handling); report the multimodal-specific carrier here without double-counting the same downstream control."
---

## Root Cause Explanation

Multimodal models don't just *see* images or *hear* audio — they read
instructions out of them. Text hidden in an image (low-contrast, tiny, or in
metadata), a directive embedded in a PDF/DOCX/SVG, or words in an audio clip the
model transcribes are all interpreted the same way as typed instructions. This
makes every non-text input a prompt-injection carrier, and a particularly
dangerous one because it bypasses the mental model (and often the moderation)
that developers apply to *text*. A feature as innocent as "upload an image and
ask about it" or "summarize this document" is an indirect prompt-injection intake.

The impact follows the same law as text prompt injection: it's a product of the
untrusted carrier reaching the model and the model's capability. If the
multimodal assistant has tools/agency or its output can auto-egress, a poisoned
image can drive tool calls or exfiltrate data. So the defenses are the same:
treat media (and any OCR/transcription derived from it) as untrusted, delimited
data; enforce privilege separation from tools; block auto-egress rendering; and
don't rely on text-only moderation. Validate and sanitize uploads
(type/size/active content) on the way in, per file_uploads.

## Vulnerable Patterns

```ts
// User image → vision model with tools/agency; hidden text in the image steers it
const answer = await agent.run({ image: userUpload, tools: [sendEmail, fetchUrl] });

// OCR/transcription of an untrusted file placed as trusted context
const text = await ocr(userPdf);
const out = await llm.complete(`Follow these notes:\n${text}`);   // document = instructions
```

Correct: media as untrusted data, privilege separation, validated uploads.

```ts
const text = await ocr(userPdf);
const out = await llm.complete({
  system: policy,
  user: `<untrusted_document>\n${text}\n</untrusted_document>`,   // delimited data
});
// tools gated by authorization outside the model; no auto-egress rendering
```

## Data Flow Tracing Guide

1. Find where user-provided images/audio/documents are sent to a model (or OCR/
   transcribed then sent).
2. Treat each as an untrusted instruction carrier; check whether it's delimited
   as data or placed as trusted context.
3. Determine the model's capability (tools/agency, output rendering/egress) to
   set blast radius.
4. Check upload validation/sanitization (type, size, active content) per
   file_uploads.
5. Note whether moderation covers media or only text.

## Evidence Checklist

- [ ] The code sending user media/OCR/transcription to the model, quoted.
- [ ] Whether it's handled as delimited untrusted data or trusted context.
- [ ] The model's capability (tools/egress) for blast radius.
- [ ] Upload validation/sanitization status.

## Attack Scenario Template

> An attacker uploads [an image with hidden instruction text / a PDF containing
> directives / an audio clip]. Because [file:line] sends it to a multimodal model
> [with tools / with auto-egress output] and treats it as trusted content, the
> model obeys the embedded instructions and [invokes a tool / exfiltrates context
> / overrides its behavior], resulting in [impact].

## Graph Mapping Instructions

- Ensure a `component:llm_boundary` node with a `depends_on` edge to
  `component:input_validation`.
- Add an `enables` edge to the tool/egress the media-injection can reach; note
  the multimodal/indirect-injection carrier in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:llm_boundary`; cross-link to prompt_injection.
