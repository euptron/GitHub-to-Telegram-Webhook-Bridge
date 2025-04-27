// If you must use this code define the expected environment variables (secrets)
// These MUST be configured in your Cloudflare Worker settings -> Secrets 
// Hence Change the following fields 
// - COS_TELEGRAM_BOT_TOKEN: Your Telegram Bot Token
// - COS_TELEGRAM_CHAT_ID: Your Telegram Supergroup Chat ID (usually negative)
// - COS_TELEGRAM_MESSAGE_THREAD_ID: The specific Topic ID within the supergroup
// - COS_TIMELESS_GITHUB_SECRETS: (Optional but Recommended) The secret you configured in the GitHub webhook settings
// If these works for you star my repository -> https://github.com/euptron/CodeOps-Studio

export default {
    async fetch(request, env, ctx) {
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

        // Request is cloned so we read the body multiple times (once for verification, once for parsing)
        const requestClone = request.clone();
        const bodyText = await requestClone.text();

        if (env.COS_TIMELESS_GITHUB_SECRETS) {
            if (!githubSignature) {
                console.error(
                    "GitHub Secret is configured, but X-Hub-Signature-256 header is missing."
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
                "COS_TIMELESS_GITHUB_SECRETS is not set. Skipping signature verification. This is insecure!"
            );
        }
        
        let payload;
        try {
            payload = JSON.parse(bodyText);
        } catch (e) {
            console.error("Failed to parse JSON payload:", e);
            return new Response("Bad Request: Invalid JSON.", { status: 400 });
        }

        let message = "";
        try {
            message = formatMessage(githubEvent, payload);
        } catch (error) {
            console.error(
                `Error formatting message for event ${githubEvent}:`,
                error
            );
            message = `⚠️ Error processing \`${escapeMarkdownV2(
                githubEvent
            )}\` event for repo \`${escapeMarkdownV2(
                payload.repository?.full_name || "unknown"
            )}\`\\.`;
        }

        if (message) {
            console.log(
                `Sending message to Telegram for event: ${githubEvent}`
            );
            ctx.waitUntil(sendTelegramMessage(message, env)); // completes after the response is sent
            return new Response("Webhook received and processing initiated.", {
                status: 202,
            });
        } else {
            console.log(
                `No message generated for event: ${githubEvent}. Sending OK response.`
            );
            return new Response(
                "Webhook received, event action not configured for notification.",
                { status: 200 }
            );
        }
    },
};

// --- HELPER FUNCTIONS ---

/**
 * Verifies the GitHub webhook signature.
 * @param {string} secret - The GitHub webhook secret.
 * @param {string} body - The raw request body text.
 * @param {string} signatureHeader - The value of the X-Hub-Signature-256 header.
 * @returns {Promise<boolean>} - True if the signature is valid, false otherwise.
 */
async function verifyGitHubSignature(secret, body, signatureHeader) {
    if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
        return false;
    }

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

/**
 * Simple buffer comparison resistant to timing attacks.
 */
async function timingSafeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    // Manual constant time comparison:
    let result = 0;
    const encoder = new TextEncoder();
    const encodedA = encoder.encode(a);
    const encodedB = encoder.encode(b);

    for (let i = 0; i < encodedA.length; i++) {
        result |= encodedA[i] ^ encodedB[i];
    }
    return result === 0;
}

/**
 * Escapes characters for Telegram MarkdownV2 parse mode.
 * @param {string} text - The input string.
 * @returns {string} - The escaped string.
 */
function escapeMarkdownV2(text) {
    if (!text) return "";
    // Escape characters: _ * [ ] ( ) ~ ` > # + - = | { } . !
    return text.replace(/([_*\[\]()~`>#+\-=|{}.!])/g, "\\$1");
}

/**
 * Formats the message based on the GitHub event type and payload.
 * @param {string} eventType - The GitHub event type (e.g., 'push', 'pull_request').
 * @param {object} payload - The parsed JSON payload from GitHub.
 * @returns {string} - The formatted message string (MarkdownV2), or empty string if not handled.
 */
function formatMessage(eventType, payload) {
    const repo = payload.repository;
    const repoName = escapeMarkdownV2(repo?.full_name || "Unknown Repo");
    const repoUrl = repo?.html_url;
    const sender = payload.sender;
    const senderName = escapeMarkdownV2(sender?.login || "Unknown User");
    const senderUrl = sender?.html_url;
    let message = `*Repo:* [${repoName}](${
        repoUrl || "#"
    }) \\| *By:* [${senderName}](${senderUrl || "#"})\\n`;

    switch (eventType) {
        case "push": {
            const ref = escapeMarkdownV2(payload.ref); // e.g., refs/heads/main
            const branch = escapeMarkdownV2(
                payload.ref.replace("refs/heads/", "").replace("refs/tags/", "")
            );
            const commits = payload.commits || [];
            const commitCount = commits.length;
            const compareUrl = payload.compare;

            if (commitCount === 0 && payload.forced) {
                message += `*Force Pushed* to branch \`${branch}\` \\(no new commits\\)\\. [Compare changes](${compareUrl})`;
            } else if (commitCount > 0) {
                message += `*Pushed ${commitCount} commit${
                    commitCount > 1 ? "s" : ""
                }* to branch \`${branch}\`\\. [Compare changes](${compareUrl})\\n`;
                commits.slice(0, 3).forEach((commit, index) => {
                    const commitMsg = escapeMarkdownV2(
                        commit.message.split("\n")[0]
                    ); // First line only
                    const commitShaShort = escapeMarkdownV2(
                        commit.id.substring(0, 7)
                    );
                    const commitUrl = commit.url;
                    message += `  \\- [${commitShaShort}](${commitUrl}) ${commitMsg} \\- _${escapeMarkdownV2(
                        commit.author.name || commit.author.username
                    )}_\\n`;
                });
                if (commitCount > 3) {
                    message += `  \\.\\.\\. and ${commitCount - 3} more\\.\\n`;
                }
            } else if (
                payload.deleted &&
                payload.ref.startsWith("refs/tags/")
            ) {
                // Handled by 'delete' event, although it may appear here too sometimes
                message = ""; // Avoid duplicate message if handled by 'delete'
            } else {
                message += `Pushed to \`${ref}\` \\(no commits detected in payload, check compare link\\)\\. [Compare changes](${compareUrl})`;
            }
            break;
        }

        case "pull_request": {
            const pr = payload.pull_request;
            const prNumber = pr.number;
            const prTitle = escapeMarkdownV2(pr.title);
            const prUrl = pr.html_url;
            const action = escapeMarkdownV2(payload.action);
            const merged = pr.merged;

            message += `*Pull Request #${prNumber}: ${prTitle}* [${action}](${prUrl})`;
            if (action === "closed") {
                message += merged ? " \\(*Merged*\\)" : " \\(*Not Merged*\\)";
            } else if (action === "assigned") {
                message += ` to ${escapeMarkdownV2(
                    payload.assignee?.login || "someone"
                )}`;
            } else if (action === "labeled") {
                message += ` with label \`${escapeMarkdownV2(
                    payload.label?.name || ""
                )}\``;
            }
            break;
        }

        case "issues": {
            const issue = payload.issue;
            const issueNumber = issue.number;
            const issueTitle = escapeMarkdownV2(issue.title);
            const issueUrl = issue.html_url;
            const action = escapeMarkdownV2(payload.action); // opened, closed, labeled, assigned, etc.

            message += `*Issue #${issueNumber}: ${issueTitle}* [${action}](${issueUrl})`;
            if (action === "assigned") {
                message += ` to ${escapeMarkdownV2(
                    payload.assignee?.login || "someone"
                )}`;
            } else if (action === "labeled") {
                message += ` with label \`${escapeMarkdownV2(
                    payload.label?.name || ""
                )}\``;
            }
            break;
        }

        case "issue_comment": {
            const issue = payload.issue;
            const comment = payload.comment;
            const action = escapeMarkdownV2(payload.action);
            const issueNumber = issue.number;
            const issueTitle = escapeMarkdownV2(issue.title);
            const commentUrl = comment.html_url;
            // Shorten comment body for preview
            let commentBody = escapeMarkdownV2(comment.body.substring(0, 150));
            if (comment.body.length > 150) {
                commentBody += "\\.\\.\\.";
            }

            if (action === "created") {
                message += `*New Comment* on Issue [#${issueNumber} ${issueTitle}](${commentUrl})\\n`;
                message += `> ${commentBody}`;
            } else {
                message += `Comment ${action} on Issue [#${issueNumber} ${issueTitle}](${commentUrl})`;
            }
            break;
        }

        case "commit_comment": {
            const comment = payload.comment;
            const action = escapeMarkdownV2(payload.action); // typically 'created'
            const commitShaShort = escapeMarkdownV2(
                comment.commit_id.substring(0, 7)
            );
            const commentUrl = comment.html_url;
            let commentBody = escapeMarkdownV2(comment.body.substring(0, 150));
            if (comment.body.length > 150) {
                commentBody += "\\.\\.\\.";
            }

            if (action === "created") {
                message += `*New Comment* on Commit [\`${commitShaShort}\`](${commentUrl})\\n`;
                message += `> ${commentBody}`;
            } else {
                message += `Comment ${action} on Commit [\`${commitShaShort}\`](${commentUrl})`;
            }
            break;
        }

        case "release": {
            const release = payload.release;
            const action = escapeMarkdownV2(payload.action); // published, created, edited, deleted, etc.
            const tagName = escapeMarkdownV2(release.tag_name);
            const releaseName = escapeMarkdownV2(
                release.name || `Release ${tagName}`
            );
            const releaseUrl = release.html_url;

            message += `*Release ${releaseName}* (${tagName}) [${action}](${releaseUrl})`;
            if (action === "published" && release.body) {
                let releaseNotes = escapeMarkdownV2(
                    release.body.substring(0, 200)
                );
                if (release.body.length > 200) {
                    releaseNotes += "\\.\\.\\.";
                }
                message += `\\n> ${releaseNotes}`;
            }
            break;
        }

        case "create": {
            const refType = escapeMarkdownV2(payload.ref_type);
            const refName = escapeMarkdownV2(payload.ref);
            message += `*Created ${refType}*: \`${refName}\``;
            break;
        }

        case "delete": {
            const refType = escapeMarkdownV2(payload.ref_type);
            const refName = escapeMarkdownV2(payload.ref);
            message += `*Deleted ${refType}*: \`${refName}\``;
            break;
        }

        case "fork": {
            const forkee = payload.forkee;
            const forkeeName = escapeMarkdownV2(forkee.full_name);
            const forkeeUrl = forkee.html_url;
            message += `*Forked* repository to [${forkeeName}](${forkeeUrl})`;
            break;
        }

        case "star": {
            const action = payload.action;
            if (action === "created") {
                const stargazerCount = payload.repository.stargazers_count;
                message += `*Starred* repository ⭐ \\(${escapeMarkdownV2(
                    stargazerCount.toString()
                )} total\\)`;
            } else if (action === "deleted") {
                const stargazerCount = payload.repository.stargazers_count;
                message += `*Unstarred* repository 💔 \\(${escapeMarkdownV2(
                    stargazerCount.toString()
                )} total\\)`;
            } else {
                message = "";
            }
            break;
        }

        case "watch": {
            const action = payload.action;
            if (action === "started") {
                const watcherCount = payload.repository.watchers_count;
                message += `*Started Watching* repository 👀 \\(${escapeMarkdownV2(
                    watcherCount.toString()
                )} total\\)`;
            } else {
                message = "";
            }
            break;
        }
        
        case "pull_request_review_comment": {
            // TODO: Handle PR review comment
            break;
        }
        
        case "discussion": {
            // TODO: Handle discussions
            break;
        }
        default:
            console.log(`Unsupported GitHub event type: ${eventType}`);
            message = "";
            break;
    }

    // Return empty message if no specific handler produced content for the event/action
    if (
        message.startsWith(
            `*Repo:* [${repoName}](${
                repoUrl || "#"
            }) \\| *By:* [${senderName}](${senderUrl || "#"})\\n`
        )
    ) {
        // Check if anything was added after the standard header
        if (
            message.length ===
            `*Repo:* [${repoName}](${
                repoUrl || "#"
            }) \\| *By:* [${senderName}](${senderUrl || "#"})\\n`.length
        ) {
            console.log(
                `No specific message generated for event: ${eventType} and action: ${
                    payload.action || "N/A"
                }`
            );
            return ""; // Don't send just the header
        }
    }

    return message.trim();
}

/**
 * Sends a message to the Telegram Bot API.
 * @param {string} text - The message text (MarkdownV2 formatted).
 * @param {object} env - The environment variables containing secrets.
 */
async function sendTelegramMessage(text, env) {
    if (!text) {
        console.log("Skipping empty message send to Telegram.");
        return;
    }

    if (
        !env.COS_TELEGRAM_BOT_TOKEN ||
        !env.COS_TELEGRAM_CHAT_ID ||
        !env.COS_TELEGRAM_MESSAGE_THREAD_ID
    ) {
        console.error(
            "Telegram secrets (TOKEN, CHAT_ID, TOPIC_ID) are not configured in worker environment."
        );
        return;
    }

    const telegramApiUrl = `https://api.telegram.org/bot${env.COS_TELEGRAM_BOT_TOKEN}/sendMessage`;
    const payload = {
        chat_id: env.COS_TELEGRAM_CHAT_ID,
        message_thread_id: env.COS_TELEGRAM_MESSAGE_THREAD_ID, // Send to specific topic
        text: text,
        parse_mode: "MarkdownV2",
        disable_web_page_preview: true, // disable link previews
    };

    try {
        const response = await fetch(telegramApiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error(
                `Telegram API Error: ${response.status} ${response.statusText}`,
                errorData
            );
        } else {
            console.log("Message successfully sent to Telegram topic.");
        }
    } catch (error) {
        console.error("Failed to send message to Telegram:", error);
    }
}
