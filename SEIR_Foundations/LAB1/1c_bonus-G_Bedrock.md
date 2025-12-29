Bedrock-powered “auto-IR” pipeline for advanced students who can actually build and demo.

The pattern below is what real orgs do: alarm → evidence collection → LLM summarization → report artifact → notify.
This will be given to you

1) Incident report template (structured, consistent, gradeable)
2) Integration framework (AWS architecture + flow)
3) Terraform skeleton resources (Chewbacca naming)
4) Lambda handler skeleton (Python) that:
    pulls alarm context
    runs CloudWatch Logs Insights queries (WAF + app)
    pulls known-good values from SSM + Secrets
    calls Bedrock Runtime InvokeModel 
    writes report to S3
    notifies via SNS
Prompt pack (so reports are high signal, not vibes)

1) Auto-generated Incident Report Template (Markdown)
You must output exact headings (easy to implement).
--> 1c_bonus-G_Bedrock.template.md


2) Integration Framework (Bedrock “Auto-IR”)
Event-driven flow
    1) CloudWatch Alarm goes to ALARM
    2) Alarm triggers SNS topic (you already have this)
    3) SNS triggers a Lambda “IncidentReporter”
    4) Lambda:
        Pulls alarm metadata from event payload
        Runs Logs Insights queries via StartQuery/GetQueryResults 
        Fetches config from SSM and Secrets Manager
        Calls Bedrock Runtime to generate the report 
        Writes Markdown + JSON evidence bundle to S3
        Publishes a “Report Ready” message to SNS (link to S3 object)

Two modes (advanced students can implement both)
    Mode A: “Fast report” (15-min window, small evidence)
    Mode B: “Deep report” (60-min window + WAF correlation + top URIs + error clustering)

Optional extra-credit: use Bedrock Agents + Knowledge Base to ingest your runbook and “recommend steps.”
# https://aws.amazon.com/blogs/machine-learning/automate-it-operations-with-amazon-bedrock-agents/?utm_source=chatgpt.com

3) Terraform Skeleton Add-on (Chewbacca naming)
Add file: bonus_G_bedrock_autoreport.tf (Folder)

4) Lambda “IncidentReporter” skeleton (Python)
Create handler.py and zip it for Terraform. (Folder)

This uses:
CloudWatch Logs Insights StartQuery/GetQueryResults 
Bedrock invoke_model via bedrock-runtime client

Note: Bedrock request body differs by model family; the framework is correct but students must adapt to the chosen model’s request schema. AWS documents InvokeModel and the runtime client.
Documentation: https://docs.aws.amazon.com/bedrock/latest/userguide/inference-invoke.html?utm_source=chatgpt.com

5) Bedrock Prompt Pack (so reports don’t hallucinate)
Include these rules in the prompt (non-negotiable):
    “Use ONLY evidence”
    “If unknown, say Unknown”
    “Include confidence levels”
    “Recommend next evidence to pull”

And add a “grading” rubric line:
    “Report must cite which query/field supports each key claim”

6) Advanced grading criteria (for your top students)
They pass “advanced” if:
    They produce both JSON evidence + Markdown report
    Report has no invented claims
    Report includes root cause classification that matches injected failure
    They redact secrets (password never appears)
    They add a second pass: “preventive actions” tied to evidence (e.g., rotation automation, SG drift detection)

Optional upgrade: Bedrock Agents + Knowledge Base (very real)
You need to store:
    runbooks (Markdown)
    common incident patterns
        in a Knowledge Base, then an Agent can recommend steps. AWS has a reference blog for automating IT ops with Agents.
Documenation: https://aws.amazon.com/blogs/machine-learning/automate-it-operations-with-amazon-bedrock-agents/?utm_source=chatgpt.com





