// Environment variables (Secrets) should be configured in Cloudflare Worker settings
// - COS_TELEGRAM_BOT_TOKEN
// - COS_TELEGRAM_CHAT_ID
// - COS_TELEGRAM_MESSAGE_THREAD_ID
// - COS_TIMELESS_GITHUB_SECRETS (Optional but Recommended)

export default {
    async fetch(request, env, ctx) {
        // --- Request validation and signature verification ---
        if (request.method !== "POST") {
            return new Response("Method Not Allowed. Expected POST.", {
                status: 405,
            });
        }
        const githubEvent = request.headers.get("X-GitHub-Event");
        const githubSignature = request.headers.get("X-Hub-Signature-256");
        const contentType = request.headers.get("content-type");

        if (!githubEvent) {
            return new Response("Missing X-GitHub-Event header.", {
                status: 400,
            });
        }
        if (!contentType || contentType !== "application/json") {
            return new Response(
                "Unsupported content-type. Expected application/json.",
                { status: 415 }
            );
        }

        const requestClone = request.clone();
        const bodyText = await requestClone.text();

        if (env.COS_TIMELESS_GITHUB_SECRETS) {
            if (!githubSignature) {
                console.error(
                    "GitHub Secret configured, but X-Hub-Signature-256 header missing."
                );
                return new Response("Forbidden. Signature required.", {
                    status: 403,
                });
            }
            try {
                const verified = await verifyGitHubSignature(
                    env.COS_TIMELESS_GITHUB_SECRETS,
                    bodyText,
                    githubSignature
                );
                if (!verified) {
                    console.error("Invalid GitHub signature.");
                    return new Response("Forbidden. Invalid signature.", {
                        status: 403,
                    });
                }
                console.log("GitHub signature verified successfully.");
            } catch (error) {
                console.error("Error verifying GitHub signature:", error);
                return new Response(
                    "Internal Server Error during signature verification.",
                    { status: 500 }
                );
            }
        } else {
            console.warn(
                "COS_TIMELESS_GITHUB_SECRETS not set. Skipping signature verification."
            );
        }
        // --- End verification ---

        let payload;
        try {
            payload = JSON.parse(bodyText);
        } catch (e) {
            console.error("Failed to parse JSON payload:", e);
            return new Response("Bad Request: Invalid JSON.", { status: 400 });
        }

        let message = "";
        try {
            message = formatMessage(githubEvent, payload, env);
        } catch (error) {
            console.error(
                `Error formatting message for event ${githubEvent}:`,
                error
            );
            const repoName = escapeMarkdownV2(
                payload.repository?.full_name || "unknown repo"
            );
            message = `⚠️ Error processing \`${escapeMarkdownV2(
                githubEvent
            )}\` event for ${repoName}`;
        }

        if (message) {
            console.log(
                `Sending message to Telegram for event: ${githubEvent}`
            );
            ctx.waitUntil(sendTelegramMessage(message, env));
            return new Response("Webhook received and processing initiated.", {
                status: 202,
            });
        } else {
            console.log(
                `No message generated for event: ${githubEvent} / action: ${
                    payload.action || "N/A"
                }.`
            );
            return new Response(
                `Webhook received, event type "${githubEvent}" ${
                    payload.action ? `(action: "${payload.action}") ` : ""
                }not configured for notification.`,
                { status: 200 }
            );
        }
    },
};

// --- Helper Functions ---

async function verifyGitHubSignature(secret, body, signatureHeader) {
    if (!signatureHeader || !signatureHeader.startsWith("sha256="))
        return false;
    const signature = signatureHeader.substring(7);
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
    const calculatedSignature = Array.from(new Uint8Array(mac))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    return await timingSafeEqual(signature, calculatedSignature);
}

async function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    const encoder = new TextEncoder();
    const encodedA = encoder.encode(a);
    const encodedB = encoder.encode(b);
    for (let i = 0; i < encodedA.length; i++)
        result |= encodedA[i] ^ encodedB[i];
    return result === 0;
}

function escapeMarkdownV2(text) {
    if (!text) return "";
    // Escape characters: _ * [ ] ( ) ~ ` > # + - = | { } . !
    // Need to escape backslashes first if they appear in the text
    text = text.replace(/\\/g, "\\\\");
    return text.replace(/([_*\[\]()~`>#+\-=|{}.!])/g, "\\$1");
}

function formatDuration(startStr, endStr) {
    if (!startStr || !endStr) return "";
    try {
        const start = new Date(startStr);
        const end = new Date(endStr);
        const durationMs = end - start;
        if (durationMs < 0) return "";

        const seconds = Math.floor(durationMs / 1000) % 60;
        const minutes = Math.floor(durationMs / (1000 * 60)) % 60;
        const hours = Math.floor(durationMs / (1000 * 60 * 60));

        let durationStr = "";
        if (hours > 0) durationStr += `${hours}h `;
        if (minutes > 0) durationStr += `${minutes}m `;
        durationStr += `${seconds}s`;

        return `(took ${escapeMarkdownV2(durationStr.trim())})`;
    } catch (e) {
        console.error("Error parsing duration:", e);
        return "";
    }
}

/**
 * Formats the message based on the GitHub event type and payload.
 * @param {string} eventType The GitHub event type.
 * @param {object} payload The parsed JSON payload from GitHub.
 * @param {object} env Environment variables.
 * @returns {string} The formatted message string (MarkdownV2), or empty string.
 */
function formatMessage(eventType, payload, env) {
    const repo = payload.repository;
    const sender = payload.sender; // User performing the action (usually)
    const organization = payload.organization; // Org context if available

    // Common elements
    const senderName = escapeMarkdownV2(sender?.login || "unknown_user");
    const senderUrl = sender?.html_url;
    const userLink = senderUrl ? `[${senderName}](${senderUrl})` : senderName;

    const repoName = escapeMarkdownV2(repo?.full_name || "");
    const repoUrl = repo?.html_url;
    // Repo link is constructed only if repoName is known
    const repoLink = repoName
        ? repoUrl
            ? `[${repoName}](${repoUrl})`
            : repoName
        : "";
    // Context usually includes 'in repoLink' but varies for org/repo-level events
    const repoContext = repoLink ? `in ${repoLink}` : "";

    let message = "";
    const action = payload.action; // Common field

    // Helper for status icons
    const getStatusIcon = (status, conclusion) => {
        if (status === "completed") {
            switch (conclusion) {
                case "success":
                    return "✅";
                case "failure":
                    return "❌";
                case "cancelled":
                    return "🚫";
                case "skipped":
                    return "⏭️";
                default:
                    return "🏁"; // Neutral completion
            }
        }
        if (status === "queued") return "⏳";
        if (status === "waiting") return "⏳";
        if (status === "in_progress") return "⚙️";
        if (status === "requested") return "🙋";
        return "ℹ️"; // Default info icon
    };

    switch (eventType) {
        // == Branch / Tag / Repo Structure ==
        case "create": {
            // Branch or tag created
            const refType = escapeMarkdownV2(payload.ref_type || "item");
            const refName = escapeMarkdownV2(payload.ref || "unknown");
            message = `${userLink} 🌱 created ${refType} \`${refName}\` ${repoContext}`;
            break;
        }
        case "delete": {
            // Branch or tag deleted
            const refType = escapeMarkdownV2(payload.ref_type || "item");
            const refName = escapeMarkdownV2(payload.ref || "unknown");
            message = `${userLink} 🗑️ deleted ${refType} \`${refName}\` from ${repoLink}`;
            break;
        }
        case "repository": {
            // Repo life cycle events
            const repoNameLink = payload.repository?.html_url
                ? `[${escapeMarkdownV2(payload.repository.full_name)}](${
                      payload.repository.html_url
                  })`
                : escapeMarkdownV2(
                      payload.repository?.full_name || "repository"
                  );
            let verb = escapeMarkdownV2(action);
            switch (action) {
                case "created":
                    verb = `✨ created repository ${repoNameLink}`;
                    break;
                case "deleted":
                    verb = `🗑️ deleted repository \`${escapeMarkdownV2(
                        payload.repository.full_name
                    )}\``;
                    break; // Link might be dead
                case "archived":
                    verb = `📦 archived repository ${repoNameLink}`;
                    break;
                case "unarchived":
                    verb = `🔓 unarchived repository ${repoNameLink}`;
                    break;
                case "publicized":
                    verb = `🌎 made repository ${repoNameLink} public`;
                    break;
                case "privatized":
                    verb = `🔒 made repository ${repoNameLink} private`;
                    break;
                case "edited":
                    verb = `✏️ edited repository ${repoNameLink}`;
                    break; // Could detail changes if needed
                case "renamed":
                    verb = `✏️ renamed repository from \`${escapeMarkdownV2(
                        payload.changes?.repository?.name?.from || "?"
                    )}\` to ${repoNameLink}`;
                    break;
                case "transferred":
                    verb = `↔️ transferred repository ${repoNameLink} (New owner: ${escapeMarkdownV2(
                        payload.repository.owner?.login || "?"
                    )})`;
                    break;
                default:
                    verb = `performed action \`${verb}\` on repository ${repoNameLink}`;
            }
            message = `${userLink} ${verb}`;
            break;
        }
        case "branch_protection_rule": {
            // Branch protection rule changes
            const rule = payload.rule;
            const ruleName = rule
                ? `rule for \`${escapeMarkdownV2(
                      rule.name || rule.pattern || "?"
                  )}\``
                : "a branch protection rule"; // Use name or pattern if available
            let verb = escapeMarkdownV2(action);
            switch (action) {
                case "created":
                    verb = `🛡️ created ${ruleName}`;
                    break;
                case "edited":
                    verb = `✏️ edited ${ruleName}`;
                    break;
                case "deleted":
                    verb = `🗑️ deleted ${ruleName}`;
                    break;
                default:
                    verb = `performed action \`${verb}\` on ${ruleName}`;
            }
            message = `${userLink} ${verb} ${repoContext}`;
            break;
        }
        // Note: 'branch_protection_configurations' event doesn't seem standard. Rule event covers specifics.

        // == CI/CD & Automation ==
        case "workflow_job": {
            const job = payload.workflow_job;
            const jobName = escapeMarkdownV2(job?.name || "job");
            const status = job?.status; // queued, in_progress, completed, waiting
            const conclusion = job?.conclusion; // success, failure, cancelled, skipped (only if status=completed)
            const icon = getStatusIcon(status, conclusion);
            const runUrl = job?.run_url;
            const runLink = runUrl
                ? `run [${escapeMarkdownV2(job.run_id)}](${runUrl})`
                : `run ${escapeMarkdownV2(job?.run_id || "?")}`;
            const duration = formatDuration(job?.started_at, job?.completed_at);

            message = `${icon} Workflow job \`${jobName}\` ${escapeMarkdownV2(
                status
            )} ${
                conclusion ? `(${escapeMarkdownV2(conclusion)}) ` : ""
            }${duration} in ${runLink} ${repoContext}`;
            break;
        }
        case "workflow_run": {
            const run = payload.workflow_run;
            const workflow = payload.workflow;
            const runName = escapeMarkdownV2(
                run?.name || workflow?.name || "workflow"
            );
            const status = run?.status; // requested, in_progress, completed, queued, waiting
            const conclusion = run?.conclusion; // success, failure, cancelled, skipped, timed_out, action_required, neutral
            const icon = getStatusIcon(status, conclusion);
            const runUrl = run?.html_url;
            const duration = formatDuration(
                run?.run_started_at,
                run?.updated_at
            ); // updated_at often marks completion time

            message = `${icon} Workflow run \`${runName}\` #${escapeMarkdownV2(
                run?.run_number || "?"
            )} ${escapeMarkdownV2(status)} ${
                conclusion ? `(${escapeMarkdownV2(conclusion)}) ` : ""
            }${duration} ${
                runUrl ? `\\([View Run](${runUrl})\\) ` : ""
            }${repoContext}`;
            if (sender?.login !== run?.actor?.login) {
                // If requester != actor
                message += ` triggered by ${escapeMarkdownV2(
                    run?.actor?.login || "?"
                )}`;
            }
            break;
        }
        case "page_build": {
            const build = payload.build;
            const status = build?.status; // building, built, errored
            const pageUrl = repoUrl
                ? `${repoUrl.replace(
                      "github.com",
                      escapeMarkdownV2(repo.owner.login) + ".github.io"
                  )}/${escapeMarkdownV2(repo.name)}`
                : ""; // Best guess for Pages URL
            let icon = "📄";
            let messageText = "";
            if (status === "built") {
                icon = "✅";
                messageText = `GitHub Pages site built successfully ${
                    pageUrl ? `\\([View Site](${pageUrl})\\) ` : ""
                }${repoContext}`;
            } else if (status === "errored") {
                icon = "❌";
                messageText = `GitHub Pages site build failed ${repoContext}`;
                if (build.error?.message) {
                    messageText += `\\n> Error: ${escapeMarkdownV2(
                        build.error.message
                    )}`;
                }
            } else if (status === "building") {
                icon = "⚙️";
                messageText = `GitHub Pages site build started ${repoContext}`;
            } else {
                messageText = `GitHub Pages build status \`${escapeMarkdownV2(
                    status
                )}\` ${repoContext}`;
            }
            message = `${icon} ${messageText}`;
            break;
        }
        case "check_suite": {
            const suite = payload.check_suite;
            const appName = escapeMarkdownV2(suite?.app?.name || "Check Suite");
            const status = suite?.status; // requested, in_progress, completed, queued
            const conclusion = suite?.conclusion; // success, failure, neutral, cancelled, timed_out, action_required, stale, skipped
            const icon = getStatusIcon(status, conclusion);
            const branch = escapeMarkdownV2(suite?.head_branch || "?");

            message = `${icon} ${appName} status \`${escapeMarkdownV2(
                status
            )}\` ${
                conclusion ? `(${escapeMarkdownV2(conclusion)}) ` : ""
            }on branch \`${branch}\` ${repoContext}`;
            // Could add link to suite/PR if available in payload
            break;
        }
        case "check_run": {
            const run = payload.check_run;
            const appName = escapeMarkdownV2(run?.app?.name || "Check Run");
            const runName = escapeMarkdownV2(run?.name || "check");
            const status = run?.status; // queued, in_progress, completed, requested, waiting, pending
            const conclusion = run?.conclusion; // success, failure, neutral, cancelled, timed_out, action_required, stale, skipped
            const icon = getStatusIcon(status, conclusion);
            const runUrl = run?.html_url;
            const duration = formatDuration(run?.started_at, run?.completed_at);

            message = `${icon} ${appName} \`${runName}\` ${escapeMarkdownV2(
                status
            )} ${
                conclusion ? `(${escapeMarkdownV2(conclusion)}) ` : ""
            }${duration} ${
                runUrl ? `\\([Details](${runUrl})\\) ` : ""
            }${repoContext}`;
            break;
        }
        case "status": {
            // Commit status API update
            const commitSha = escapeMarkdownV2(
                payload.sha?.substring(0, 7) || "commit"
            );
            const statusState = escapeMarkdownV2(payload.state); // error, failure, pending, success
            const context = escapeMarkdownV2(payload.context || "Status");
            const description = escapeMarkdownV2(payload.description || "");
            const targetUrl = payload.target_url;
            let icon = "ℹ️";
            if (statusState === "success") icon = "✅";
            if (statusState === "failure" || statusState === "error")
                icon = "❌";
            if (statusState === "pending") icon = "⏳";

            message = `${icon} Status \`${context}\` updated to \`${statusState}\` for \`${commitSha}\` ${repoContext}`;
            if (description) message += `\\n> ${description}`;
            if (targetUrl) message += ` \\([Details](${targetUrl})\\)`;
            break;
        }

        // == Issues / PRs / Discussions ==
        case "issues": {
            // Existing logic covers most actions, added 'typed'/'untyped'
            const issue = payload.issue;
            const action = payload.action;
            const issueNumber = issue?.number;
            const issueTitle = escapeMarkdownV2(
                issue?.title || `Issue #${issueNumber || "?"}`
            );
            const issueUrl = issue?.html_url;

            if (!issueNumber) {
                console.warn("Issue event missing number.");
                return "";
            }
            if (!issueUrl && action !== "deleted") {
                console.warn("Issue event missing URL.");
                return "";
            }

            let actionText = `performed action \`${escapeMarkdownV2(
                action
            )}\` on`; // Fallback
            let subject = `issue [#${issueNumber} ${issueTitle}](${
                issueUrl || "#"
            })`;
            let details = "";

            switch (action) {
                case "opened":
                    actionText = `opened`;
                    break;
                case "closed":
                    actionText = `closed`;
                    break;
                case "reopened":
                    actionText = `reopened`;
                    break;
                case "edited":
                    actionText = `edited`;
                    break;
                case "assigned":
                    actionText = `assigned`;
                    subject = `issue [#${issueNumber}](${issueUrl})`;
                    details = `to ${escapeMarkdownV2(
                        payload.assignee?.login || "someone"
                    )}`;
                    break;
                case "unassigned":
                    actionText = `unassigned ${escapeMarkdownV2(
                        payload.assignee?.login || "someone"
                    )} from`;
                    subject = `issue [#${issueNumber}](${issueUrl})`;
                    break;
                case "labeled":
                    actionText = `added label`;
                    subject = `\`${escapeMarkdownV2(
                        payload.label?.name || "?"
                    )}\` to issue [#${issueNumber}](${issueUrl})`;
                    break;
                case "unlabeled":
                    actionText = `removed label`;
                    subject = `\`${escapeMarkdownV2(
                        payload.label?.name || "?"
                    )}\` from issue [#${issueNumber}](${issueUrl})`;
                    break;
                case "locked":
                    actionText = `locked conversation on`;
                    details = payload.issue?.active_lock_reason
                        ? `(reason: _${escapeMarkdownV2(
                              payload.issue.active_lock_reason
                          )}_)`
                        : "";
                    break;
                case "unlocked":
                    actionText = `unlocked conversation on`;
                    break;
                case "deleted":
                    actionText = `deleted`;
                    subject = `issue \`#${issueNumber} ${issueTitle}\``; // URL is invalid
                    break;
                case "transferred":
                    actionText = `transferred`;
                    break;
                case "pinned":
                    actionText = `📌 pinned`;
                    break;
                case "unpinned":
                    actionText = `📌 unpinned`;
                    break;
                case "milestoned":
                    actionText = `added`;
                    subject = `issue [#${issueNumber}](${issueUrl}) to milestone \`${escapeMarkdownV2(
                        payload.milestone?.title || "?"
                    )}\``;
                    break;
                case "demilestoned":
                    actionText = `removed`;
                    subject = `issue [#${issueNumber}](${issueUrl}) from milestone \`${escapeMarkdownV2(
                        payload.milestone?.title || "?"
                    )}\``;
                    break;
                case "typed": // New Issue type field
                    actionText = `changed type of`;
                    subject = `issue [#${issueNumber}](${issueUrl})`;
                    // Payload structure for 'typed' needs confirmation - assuming 'issue.type' exists
                    details = payload.issue?.type
                        ? `to \`${escapeMarkdownV2(payload.issue.type)}\``
                        : "";
                    break;
                case "untyped": // Hypothetical - not standard? Handle similarly if it exists.
                    actionText = `removed type from`;
                    subject = `issue [#${issueNumber}](${issueUrl})`;
                    break;
                default:
                    actionText = `performed action \`${escapeMarkdownV2(
                        action
                    )}\` on`;
            }
            message = `${userLink} ${actionText} ${subject} ${details} ${repoContext}`;
            break;
        }
        case "pull_request": {
            // Existing logic covers most, added 'enqueued', 'dequeued'
            const pr = payload.pull_request;
            const action = payload.action;
            const prNumber = pr?.number;
            const prTitle = escapeMarkdownV2(
                pr?.title || `PR #${prNumber || "?"}`
            );
            const prUrl = pr?.html_url;

            if (!prNumber || !prUrl) {
                console.warn("PR event missing number or URL.");
                return "";
            }

            let actionText = `performed action \`${escapeMarkdownV2(
                action
            )}\` on`; // Fallback
            let subject = `pull request [#${prNumber} ${prTitle}](${prUrl})`;
            let details = "";

            switch (action) {
                case "opened":
                    actionText = `opened`;
                    break;
                case "closed":
                    actionText = pr?.merged ? `✅ merged` : `closed`;
                    if (pr?.merged_by)
                        details = `by ${escapeMarkdownV2(pr.merged_by.login)}`;
                    break;
                case "reopened":
                    actionText = `reopened`;
                    break;
                case "edited":
                    actionText = `edited`;
                    break;
                case "assigned":
                    actionText = `assigned`;
                    subject = `pull request [#${prNumber}](${prUrl})`;
                    details = `to ${escapeMarkdownV2(
                        payload.assignee?.login || "someone"
                    )}`;
                    break;
                case "unassigned":
                    actionText = `unassigned ${escapeMarkdownV2(
                        payload.assignee?.login || "someone"
                    )} from`;
                    subject = `pull request [#${prNumber}](${prUrl})`;
                    break;
                case "review_requested":
                    actionText = `requested a review from`;
                    let reviewer = "someone";
                    if (payload.requested_reviewer)
                        reviewer = escapeMarkdownV2(
                            payload.requested_reviewer.login
                        );
                    else if (payload.requested_team)
                        reviewer = `team \`${escapeMarkdownV2(
                            payload.requested_team.name
                        )}\``;
                    subject = `${reviewer} on pull request [#${prNumber}](${prUrl})`;
                    break;
                case "review_request_removed":
                    actionText = `removed review request for`;
                    let removedReviewer = "someone";
                    if (payload.requested_reviewer)
                        removedReviewer = escapeMarkdownV2(
                            payload.requested_reviewer.login
                        );
                    else if (payload.requested_team)
                        removedReviewer = `team \`${escapeMarkdownV2(
                            payload.requested_team.name
                        )}\``;
                    subject = `${removedReviewer} on pull request [#${prNumber}](${prUrl})`;
                    break;
                case "labeled":
                    actionText = `added label`;
                    subject = `\`${escapeMarkdownV2(
                        payload.label?.name || "?"
                    )}\` to pull request [#${prNumber}](${prUrl})`;
                    break;
                case "unlabeled":
                    actionText = `removed label`;
                    subject = `\`${escapeMarkdownV2(
                        payload.label?.name || "?"
                    )}\` from pull request [#${prNumber}](${prUrl})`;
                    break;
                case "synchronize":
                    actionText = `pushed updates to`;
                    break;
                case "ready_for_review":
                    actionText = `marked as ready for review`;
                    break;
                case "converted_to_draft":
                    actionText = `marked as draft`;
                    break;
                case "locked":
                    actionText = `locked conversation on`;
                    details = payload.pull_request?.active_lock_reason
                        ? `(reason: _${escapeMarkdownV2(
                              payload.pull_request.active_lock_reason
                          )}_)`
                        : "";
                    break;
                case "unlocked":
                    actionText = `unlocked conversation on`;
                    break;
                case "auto_merge_enabled":
                    actionText = `enabled auto\\-merge on`;
                    break;
                case "auto_merge_disabled":
                    actionText = `disabled auto\\-merge on`;
                    break;
                case "milestoned":
                    actionText = `added`;
                    subject = `pull request [#${prNumber}](${prUrl}) to milestone \`${escapeMarkdownV2(
                        payload.milestone?.title || "?"
                    )}\``;
                    break;
                case "demilestoned":
                    actionText = `removed`;
                    subject = `pull request [#${prNumber}](${prUrl}) from milestone \`${escapeMarkdownV2(
                        payload.milestone?.title || "?"
                    )}\``;
                    break;
                case "enqueued":
                    actionText = `enqueued`;
                    break; // Merge Queue
                case "dequeued":
                    actionText = `dequeued`;
                    break; // Merge Queue
                default:
                    actionText = `performed action \`${escapeMarkdownV2(
                        action
                    )}\` on`;
            }
            message = `${userLink} ${actionText} ${subject} ${details} ${repoContext}`;
            break;
        }
        case "pull_request_review": {
            const review = payload.review;
            const pr = payload.pull_request;
            const prNumber = pr?.number;
            const prUrl = pr?.html_url;
            const reviewState = escapeMarkdownV2(review?.state); // commented, approved, changes_requested, dismissed
            const reviewUrl = review?.html_url;

            if (!prNumber || !prUrl) {
                console.warn("PR Review event missing PR info.");
                return "";
            }

            let actionText = `submitted a review`;
            let stateText = `(\`${reviewState}\`)`;
            let icon = "👀";
            if (reviewState === "approved") {
                icon = "✅";
                stateText = `approved the changes`;
            }
            if (reviewState === "changes_requested") {
                icon = "⚠️";
                stateText = `requested changes`;
            }
            if (reviewState === "commented") {
                icon = "💬";
                stateText = `commented`;
            }
            if (reviewState === "dismissed") {
                icon = "🚫";
                stateText = `dismissed a review`;
            }

            message = `${userLink} ${icon} ${stateText} on pull request [#${prNumber}](${prUrl}) ${
                reviewUrl ? `\\([View Review](${reviewUrl})\\) ` : ""
            }${repoContext}`;
            // Add review body preview if it exists and state is 'commented' or has a body
            if (review?.body) {
                let body = escapeMarkdownV2(review.body.substring(0, 150));
                if (review.body.length > 150) body += "\\.\\.\\.";
                if (body) message += `\\n> ${body}`;
            }
            break;
        }
        case "pull_request_review_thread": {
            const thread = payload.thread;
            const pr = payload.pull_request;
            const prNumber = pr?.number;
            const prUrl = pr?.html_url;

            if (!prNumber || !prUrl || !thread?.comments?.length) {
                console.warn("PR Review Thread event missing info.");
                return "";
            }

            // Get URL of the first comment in the thread as context
            const threadUrl = thread.comments[0].html_url;
            let verb = escapeMarkdownV2(action);
            if (action === "resolved") verb = "✅ resolved a review thread";
            if (action === "unresolved") verb = " reopened a review thread";

            message = `${userLink} ${verb} on pull request [#${prNumber}](${prUrl}) ${
                threadUrl ? `\\([View Thread](${threadUrl})\\) ` : ""
            }${repoContext}`;
            break;
        }
        case "issue_comment":
        case "pull_request_review_comment": {
            // Handles comments on PR diffs
            const comment = payload.comment;
            const action = payload.action;
            const issue = payload.issue; // Issue context (for issue comments)
            const pr = payload.pull_request; // PR context (for PR review comments)
            const commentUrl = comment?.html_url;
            let targetLink = "an item"; // Fallback

            // Determine target based on available context
            if (pr?.number) {
                targetLink = `pull request [#${pr.number} ${escapeMarkdownV2(
                    pr.title || ""
                )}](${pr.html_url || "#"})`;
            } else if (issue?.number) {
                targetLink = `issue [#${issue.number} ${escapeMarkdownV2(
                    issue.title || ""
                )}](${issue.html_url || "#"})`;
            }

            if (!commentUrl || action === "deleted") {
                message = `${userLink} ${escapeMarkdownV2(
                    action
                )} a comment on ${targetLink} ${repoContext}`;
            } else {
                let verb = "commented on";
                if (action === "edited") verb = "edited a comment on";
                message = `${userLink} ${verb} ${targetLink} ${repoContext} \\([View Comment](${commentUrl})\\)`;
                let body = escapeMarkdownV2(
                    (comment.body || "").substring(0, 150)
                );
                if (comment.body && comment.body.length > 150)
                    body += "\\.\\.\\.";
                if (body) message += `\\n> ${body}`;
            }
            break;
        }
        case "commit_comment": {
            // Comment on a specific commit (not part of a PR review)
            const comment = payload.comment;
            const action = payload.action;
            const commitShaShort = escapeMarkdownV2(
                comment?.commit_id?.substring(0, 7) || "unknown"
            );
            const commentUrl = comment?.html_url;

            if (!commentUrl || action === "deleted") {
                message = `${userLink} ${escapeMarkdownV2(
                    action
                )} a comment on commit \`${commitShaShort}\` ${repoContext}`;
            } else {
                let verb = "commented on";
                if (action === "edited") verb = "edited a comment on";
                message = `${userLink} ${verb} commit [\`${commitShaShort}\`](${commentUrl}) ${repoContext}`;
                let body = escapeMarkdownV2(
                    (comment.body || "").substring(0, 150)
                );
                if (comment.body && comment.body.length > 150)
                    body += "\\.\\.\\.";
                if (body) message += `\\n> ${body}`;
            }
            break;
        }
        case "discussion": {
            const discussion = payload.discussion;
            const discussionTitle = escapeMarkdownV2(
                discussion?.title || "discussion"
            );
            const discussionUrl = discussion?.html_url;
            let verb = escapeMarkdownV2(action);
            let details = "";

            switch (action) {
                case "created":
                    verb = `💬 created discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "edited":
                    verb = `✏️ edited discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "deleted":
                    verb = `🗑️ deleted discussion \`${discussionTitle}\``;
                    break;
                case "pinned":
                    verb = `📌 pinned discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "unpinned":
                    verb = `📌 unpinned discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "locked":
                    verb = `🔒 locked discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "unlocked":
                    verb = `🔓 unlocked discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "transferred":
                    verb = `↔️ transferred discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "category_changed":
                    verb = `🔄 changed category for discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "answered":
                    verb = `✅ marked discussion [${discussionTitle}](${discussionUrl}) as answered`;
                    break;
                case "unanswered":
                    verb = `❓ marked discussion [${discussionTitle}](${discussionUrl}) as unanswered`;
                    break;
                case "labeled":
                    details = `label \`${escapeMarkdownV2(
                        payload.label?.name || "?"
                    )}\` to`;
                    verb = `added ${details} discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                case "unlabeled":
                    details = `label \`${escapeMarkdownV2(
                        payload.label?.name || "?"
                    )}\` from`;
                    verb = `removed ${details} discussion [${discussionTitle}](${discussionUrl})`;
                    break;
                default:
                    verb = `performed action \`${verb}\` on discussion [${discussionTitle}](${discussionUrl})`;
            }
            message = `${userLink} ${verb} ${repoContext}`;
            break;
        }
        case "discussion_comment": {
            const comment = payload.comment;
            const discussion = payload.discussion;
            const commentUrl = comment?.html_url;
            const discussionLink = discussion?.html_url
                ? `discussion [${escapeMarkdownV2(discussion.title)}](${
                      discussion.html_url
                  })`
                : "a discussion";

            if (!commentUrl || action === "deleted") {
                message = `${userLink} ${escapeMarkdownV2(
                    action
                )} a comment on ${discussionLink} ${repoContext}`;
            } else {
                let verb = "commented on";
                if (action === "edited") verb = "edited a comment on";
                message = `${userLink} ${verb} ${discussionLink} ${repoContext} \\([View Comment](${commentUrl})\\)`;
                let body = escapeMarkdownV2(
                    (comment.body || "").substring(0, 150)
                );
                if (comment.body && comment.body.length > 150)
                    body += "\\.\\.\\.";
                if (body) message += `\\n> ${body}`;
            }
            break;
        }
        case "label": {
            // Label definition created/edited/deleted
            const labelName = escapeMarkdownV2(payload.label?.name || "label");
            let verb = escapeMarkdownV2(action);
            switch (action) {
                case "created":
                    verb = `🏷️ created label \`${labelName}\``;
                    break;
                case "edited":
                    verb = `✏️ edited label \`${labelName}\``;
                    break;
                case "deleted":
                    verb = `🗑️ deleted label \`${labelName}\``;
                    break;
                default:
                    verb = `performed action \`${verb}\` on label \`${labelName}\``;
            }
            message = `${userLink} ${verb} ${repoContext}`;
            break;
        }

        // == Security & Dependencies ==
        case "dependabot_alert": {
            const alert = payload.alert;
            const state = alert?.state; // open, fixed, dismissed, auto_dismissed, auto_reopened
            const severity = escapeMarkdownV2(
                alert?.security_advisory?.severity || "?"
            ); // low, medium, high, critical
            const packageName = escapeMarkdownV2(
                alert?.security_vulnerability?.package?.name || "dependency"
            );
            const alertUrl = alert?.html_url;
            let verb = escapeMarkdownV2(action);
            let icon = "⚠️";

            switch (action) {
                case "created":
                    verb = `created Dependabot alert (\`${severity}\`) for \`${packageName}\``;
                    break;
                case "fixed":
                    verb = `✅ fixed Dependabot alert for \`${packageName}\``;
                    icon = "✅";
                    break;
                case "dismissed":
                    verb = `🚫 dismissed Dependabot alert for \`${packageName}\``;
                    icon = "🚫";
                    break;
                case "reopened":
                    verb = `reopened Dependabot alert for \`${packageName}\``;
                    break;
                case "auto_dismissed":
                    verb = `🚫 auto\\-dismissed Dependabot alert for \`${packageName}\``;
                    icon = "🚫";
                    break;
                case "auto_reopened":
                    verb = `reopened Dependabot alert for \`${packageName}\``;
                    break;
                case "reintroduced":
                    verb = `🔄 reintroduced Dependabot alert for \`${packageName}\``;
                    break;
                default:
                    verb = `performed action \`${verb}\` on Dependabot alert for \`${packageName}\``;
            }
            message = `${userLink} ${icon} ${verb} ${repoContext} ${
                alertUrl ? `\\([Details](${alertUrl})\\)` : ""
            }`;
            break;
        }
        case "code_scanning_alert": {
            const alert = payload.alert;
            const ruleDesc = escapeMarkdownV2(
                alert?.rule?.description || "Code scanning rule"
            );
            const alertUrl = alert?.html_url;
            const alertNumber = alert?.number;
            let verb = escapeMarkdownV2(action);
            let icon = "🛡️";

            switch (action) {
                case "created":
                    verb = `found new alert [#${alertNumber}](${alertUrl}): ${ruleDesc}`;
                    break;
                case "fixed":
                    verb = `✅ fixed alert [#${alertNumber}](${alertUrl}): ${ruleDesc}`;
                    icon = "✅";
                    break;
                case "closed_by_user":
                    verb = `🚫 closed alert [#${alertNumber}](${alertUrl}) as "${escapeMarkdownV2(
                        alert.dismissed_reason || "?"
                    )}"`;
                    icon = "🚫";
                    break; // Reason: false positive, won't fix, used in tests
                case "reopened_by_user":
                    verb = ` reopened alert [#${alertNumber}](${alertUrl}): ${ruleDesc}`;
                    break;
                case "reopened":
                    verb = ` reopened alert [#${alertNumber}](${alertUrl}): ${ruleDesc}`;
                    break; // Generic reopen
                case "appeared_in_branch":
                    verb = `alert [#${alertNumber}](${alertUrl}) appeared in branch \`${escapeMarkdownV2(
                        payload.ref || "?"
                    )}\``;
                    break;
                // Add more actions if needed: closed (by system), dismissed (deprecated alias)
                default:
                    verb = `performed action \`${verb}\` on alert [#${alertNumber}](${alertUrl}): ${ruleDesc}`;
            }
            message = `${
                userLink ||
                escapeMarkdownV2(
                    payload.commit_oid?.substring(0, 7) || "Code Scanning"
                )
            } ${icon} ${verb} ${repoContext}`;
            break;
        }

        // == Misc / Meta ==
        case "fork": {
            // Repo forked
            const forkeeName = escapeMarkdownV2(
                payload.forkee?.full_name || "unknown"
            );
            const forkeeUrl = payload.forkee?.html_url;
            const forkeeLink = forkeeUrl
                ? `[${forkeeName}](${forkeeUrl})`
                : forkeeName;
            message = `${userLink} 🍴 forked ${repoLink} to ${forkeeLink}`;
            break;
        }
        case "star": {
            // Repo starred/unstarred
            if (action === "created")
                message = `${userLink} 🌟 starred ${repoLink}`;
            else if (action === "deleted")
                message = `${userLink} 💔 unstarred ${repoLink}`;
            else message = "";
            break;
        }
        case "watch": {
            // User starts watching (legacy - star is preferred)
            if (action === "started")
                message = `${userLink} 👀 started watching ${repoLink}`;
            else message = "";
            break;
        }
        case "release": {
            // Release published, edited, etc.
            const release = payload.release;
            const tagName = escapeMarkdownV2(release?.tag_name || "tag?");
            const releaseName = escapeMarkdownV2(
                release?.name || tagName || "release?"
            );
            const releaseUrl = release?.html_url;

            if (!releaseUrl && action !== "deleted") {
                message = `${userLink} performed action \`${escapeMarkdownV2(
                    action
                )}\` on release \`${releaseName}\` ${repoContext}`;
            } else {
                let actionText = `performed action \`${escapeMarkdownV2(
                    action
                )}\` on`;
                let subject = `release [${releaseName}](${releaseUrl || "#"})`;
                switch (action) {
                    case "published":
                        actionText = `📦 published`;
                        break;
                    case "unpublished":
                        actionText = `unpublished`;
                        break;
                    case "created":
                        actionText = `created release draft`;
                        break;
                    case "edited":
                        actionText = `edited`;
                        break;
                    case "deleted":
                        actionText = `deleted`;
                        subject = `release \`${releaseName}\``;
                        break;
                    case "prereleased":
                        actionText = `published pre-release`;
                        break;
                    case "released":
                        actionText = `published release`;
                        break;
                }
                message = `${userLink} ${actionText} ${subject} ${repoContext}`;

                if (
                    [
                        "published",
                        "created",
                        "prereleased",
                        "released",
                    ].includes(action) &&
                    release?.body
                ) {
                    let notes = escapeMarkdownV2(
                        release.body.substring(0, 200)
                    );
                    if (release.body.length > 200) notes += "\\.\\.\\.";
                    if (notes) message += `\\n> ${notes}`;
                }
            }
            break;
        }
        case "package": {
            // GitHub Package published/updated
            const pkg = payload.package;
            const pkgVersion = escapeMarkdownV2(
                pkg?.package_version?.version || "?"
            );
            const pkgName = escapeMarkdownV2(pkg?.name || "package");
            const pkgType = escapeMarkdownV2(pkg?.package_type || "?"); // npm, maven, docker, nuget, rubygems, container
            const pkgUrl = pkg?.html_url;
            let verb = escapeMarkdownV2(action);
            if (action === "published")
                verb = `📦 published ${pkgType} package \`${pkgName}\` version \`${pkgVersion}\``;
            if (action === "updated")
                verb = `🔄 updated ${pkgType} package \`${pkgName}\``; // Might not include version

            message = `${userLink} ${verb} ${repoContext} ${
                pkgUrl ? `\\([View Package](${pkgUrl})\\)` : ""
            }`;
            break;
        }
        case "gollum": {
            // Wiki page updated
            const pages = payload.pages || [];
            const pageCount = pages.length;
            if (pageCount > 0) {
                const firstPage = pages[0];
                const pageName = escapeMarkdownV2(firstPage.page_name || "?");
                const pageAction = escapeMarkdownV2(
                    firstPage.action || "updated"
                ); // created, edited
                const pageUrl = firstPage.html_url;
                message = `${userLink} wiki page \`${pageName}\` ${pageAction} ${
                    pageUrl ? `\\([View Page](${pageUrl})\\) ` : ""
                }${repoContext}`;
                if (pageCount > 1)
                    message += ` (and ${pageCount - 1} other${
                        pageCount > 2 ? "s" : ""
                    })`;
            } else {
                message = `${userLink} updated the wiki ${repoContext}`; // Fallback
            }
            break;
        }
        case "team": {
            // Team edited (permissions change) or repo added/removed from team
            const teamName = escapeMarkdownV2(payload.team?.name || "team");
            const teamUrl = payload.team?.html_url;
            const teamLink = teamUrl
                ? `[${teamName}](${teamUrl})`
                : `\`${teamName}\``;
            let verb = escapeMarkdownV2(action);
            // Note: 'added_to_repository' / 'removed_from_repository' actions are on the REPOSITORY payload, not team event usually.
            // This event focuses on team definition changes or adding repo TO a team.
            switch (action) {
                case "created":
                    verb = `created team ${teamLink}`;
                    break; // Org level usually
                case "deleted":
                    verb = `deleted team \`${teamName}\``;
                    break; // Org level usually
                case "edited":
                    verb = `✏️ edited team ${teamLink}`;
                    break;
                case "added_to_repository":
                    verb = `added ${repoLink} to team ${teamLink}`;
                    break; // This is less common event trigger
                case "removed_from_repository":
                    verb = `removed ${repoLink} from team ${teamLink}`;
                    break; // Less common
                default:
                    verb = `performed action \`${verb}\` regarding team ${teamLink}`;
            }
            // Sender might be less relevant if it's an org admin action
            message = `Team action: ${verb}`; // Simpler message for team events
            break;
        }

        default:
            console.log(
                `-> Unsupported GitHub event type received: ${eventType}`
            );
            message = ""; // No message for unsupported events by default
            break;
    }

    return message.trim(); // Return final message or empty string
}

async function sendTelegramMessage(text, env) {
    if (!text) {
        console.log("Skipping empty message send to Telegram.");
        return;
    }
    // Check for essential secrets
    if (
        !env.COS_TELEGRAM_BOT_TOKEN ||
        !env.COS_TELEGRAM_CHAT_ID ||
        !env.COS_TELEGRAM_MESSAGE_THREAD_ID
    ) {
        console.error(
            "Telegram secrets (TOKEN, CHAT_ID, TOPIC_ID) missing or incomplete in worker environment."
        );
        return;
    }

    const telegramApiUrl = `https://api.telegram.org/bot${env.COS_TELEGRAM_BOT_TOKEN}/sendMessage`;
    const apiPayload = {
        chat_id: env.COS_TELEGRAM_CHAT_ID,
        message_thread_id: env.COS_TELEGRAM_MESSAGE_THREAD_ID,
        text: text,
        parse_mode: "MarkdownV2",
        disable_web_page_preview: true,
    };

    try {
        const response = await fetch(telegramApiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(apiPayload),
        });

        if (!response.ok) {
            const errorData = await response.text(); // Read body as text for detailed error info
            console.error(
                `Telegram API Error: ${response.status} ${response.statusText}. ChatID: ${env.COS_TELEGRAM_CHAT_ID}, TopicID: ${env.COS_TELEGRAM_MESSAGE_THREAD_ID}. Response: ${errorData}`
            );
        } else {
            console.log(
                `Message sent successfully to Telegram topic ${env.COS_TELEGRAM_MESSAGE_THREAD_ID}.`
            );
        }
    } catch (error) {
        console.error(
            "Failed to send message to Telegram (network/fetch error):",
            error
        );
    }
}
