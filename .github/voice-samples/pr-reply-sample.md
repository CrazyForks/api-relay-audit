Thanks for the thoughtful PR and the time you put into these 7 improvements!

After careful evaluation, we've decided to hold off on merging for now. Here's our reasoning:

**#1 SSL `-k` removal**: The tool's primary use case is auditing untrusted relays — many of which use self-signed or misconfigured certificates. Removing `-k` by default would break the tool for a large portion of real-world targets. For an audit tool (not a production client), defaulting to `-k` is the pragmatic choice.

**#2 Prompt extraction detection**: No false-positive reports from users yet. The current keyword approach is simple and has been working. We'd prefer to wait for real user feedback before adding regex complexity.

**#4 Identity test debiasing**: The hardcoded `amazon`/`kiro`/`aws` keywords match the most common real-world injection patterns we've observed. A generic approach adds complexity without proven need.

**#5 JSON output**: Nice feature, but no user has requested it yet. We'd rather keep the interface minimal until there's demand.

**#7 Branch URL fix**: We verified that both `main` and `master` URLs resolve correctly on GitHub (200 status). No 404 issue exists.

**#3 Retry and #6 Canary randomization**: As noted in the review, these need some adjustments before they'd be ready.

**Our approach**: We're keeping the codebase user-feedback-driven rather than speculative. When users report false positives (#2), need JSON output (#5), or encounter SSL issues (#1), we'll revisit these changes.

We genuinely appreciate the contribution. Feel free to open focused PRs for individual changes as real-world use cases emerge!
