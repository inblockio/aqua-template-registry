# Push-style subscription upgrade path

Status: design note, not implemented.

Date: 2026-08-07

Backlog item R6: "Push-style subscription upgrade path (SSE or webhooks) as
a design note first; polling stays the compatibility baseline." This is
that note. It contains no code and proposes none for immediate
implementation.

## 1. The problem, stated honestly

Today a consumer polls `GET /publishers/{did}/feed?since=<seq>` on an
interval (`--interval`, default 30 seconds in `subscribe`), persists the
returned `next` cursor, and repeats. The README calls this deliberate:
"There is no push and no websocket and no long poll: polling is
restart-safe and the server keeps no per-consumer state, which is the
entire point."

Push would buy exactly two things:

- **Lower latency from publish to a consumer noticing.** At a 30 second
  poll interval, notice lags publication by up to 30 seconds, half that on
  average. Push collapses this to roughly one round trip.
- **Less wasted load when a registry has many idle subscribers.** Ten
  thousand subscribers polling every 30 seconds is about 333 feed requests
  per second even when nothing changed, because a poll cannot know the
  answer is "nothing new" without asking.

It buys nothing else. It does not change what gets verified, and does not
remove the need to fetch and check a registration, its definition body, or
the feed head before importing (section 2).

Concretely, this is a template registry: publishers register vendors,
templates, and aliases, and the seeded audit-set-v1 is twelve registrations
committed once. A realistic deployment sees a handful of registrations a
week, not a second. At that rate 30 second latency is almost never the
binding constraint; the constraint is a human deciding whether to trust a
new publisher or pin a new name (README, "Importing: the consumer side").
Push has nothing to offer against a bottleneck that is a person reading a
diff. Polling already satisfies every deployment this project has today.
This note answers "what if that stops being true," not "this is a problem
now."

## 2. The constraint that shapes the whole decision

Verification is unchanged by transport. This is the organising principle
for both options below.

Everything a subscriber acts on is one of three things, each checked after
it arrives, never before:

- A signed Aqua tree (vendor, template, or alias registration), verified
  through `aqua-rs-sdk-core` under the strict policy (`src/import.rs`).
- A content-addressed body (a template definition), rehashed with
  `calculate_link` and compared against the `template_hash` a registration
  claims (verification chain step 6 in the README).
- A signed feed head (`src/feedhead.rs`), checked for signature and
  self-certification, then checked against the entries on hand for
  withholding, reordering, rollback, and equivocation
  (`Subscriber::check_head` in `src/subscribe.rs`).

None of these checks gets cheaper or unnecessary because the subscriber
learned about a change over a push channel rather than a poll response. A
push notification cannot substitute for any of them; it can only trigger
the subscriber to run the same sync it already runs. In practice this means
a push payload is an untrusted hint ("publisher X may have something new,
go check"), and the reaction to it is an unmodified call to
`Subscriber::sync`, which fetches the feed, verifies the head, and only
then imports. Push is a notification mechanism, never a delivery mechanism.
A design that let a push payload carry template content, skip the head
check, or advance the cursor directly would reopen the withholding,
reordering, rollback, and equivocation holes `src/feedhead.rs` exists to
close, just over a different wire protocol. Both options below are judged
against this line, not against implementation convenience.

## 3. Option A: Server-Sent Events

**Fit.** `src/http.rs` builds one `axum::Router` whose handlers all return
buffered `Json<T>` or `String` bodies; nothing streams today. SSE would add
one route, something like `GET /publishers/{did}/events`, returning a
streaming `axum::response::sse::Sse` response whose events carry only the
publisher's latest `seq` (and optionally `head_seq`). `get_feed` would not
change. The event payload is the same integer the `since`/`next` cursor
already uses, so no new correlation scheme is needed between the two
transports, and SSE's `Last-Event-ID` reconnect convention could carry that
same `seq` if wanted, though because the payload is only ever a hint, a
reconnect that lost events is harmless: the next poll notices the gap.

**Cost.** One held connection per subscriber for as long as it wants low
latency, a real (if modest) departure from "the server keeps no
per-consumer state," since the registry now holds live socket state, even
though the durable cursor still lives only with the subscriber. Keep-alive
traffic is needed to detect a dead connection. Reverse proxies, which this
project's own deployment model already assumes in front of `registryd`
(README, "No transport security in the client"), commonly buffer responses
by default and will break SSE unless configured otherwise, a footgun in
infrastructure this project does not control. Reconnect logic beyond
`Last-Event-ID` still has to be hand-rolled, similar in kind to the retry
logic polling already has (`Subscriber::collect_feed`'s page loop, the
CLI's `--interval` loop).

**What it gives.** Works through firewalls and NATs permitting only
outbound connections, because the subscriber opens the connection and the
registry only writes to a socket the subscriber initiated; no inbound
listener needed on the consumer, matching how `src/httpclient.rs` and the
`client` feature are built today. It layers directly onto the existing feed:
the event is a cursor hint, and `Subscriber::sync` already knows what to do
with one, so the new code is "wake sync early" plus the poll fallback in
section 7.

## 4. Option B: Webhooks

**Fit.** The registry would need a registration endpoint, something like
`POST /publishers/{did}/webhooks` accepting a callback URL, storage for that
mapping, and a delivery worker that POSTs a small notification to the URL
whenever the publisher's feed advances.

**Cost.** The consumer must run a reachable HTTPS listener, the opposite of
today's design: `src/httpclient.rs` and `src/bin/subscribe.rs` are
deliberately a small outbound-only client, and the `client` Cargo feature
is split from `server` precisely so a consumer that only imports templates
never links `axum` (`Cargo.toml`). Webhooks require every consumer to
become a server, reintroducing the entire `server` dependency subtree for
what is supposed to be the lightweight half of this crate. Beyond that:
delivery retries and backoff per consumer per publisher; a dead-letter
story for when the registry gives up on a consumer; per-consumer state
(callback URL, retry counters, delivery history) where today there is
none, a direct reversal of what the README calls "the entire point" of
polling; the registry becomes a general-purpose outbound requester against
URLs supplied by third parties, textbook SSRF territory (link-local
ranges, internal service ports, a URL that resolves differently tomorrow
than when registered) unless egress is deliberately constrained, none of
which exists in this codebase today; and per-consumer failure isolation, so
one dead endpoint cannot affect delivery to any other consumer.

The asymmetry is the point: webhooks move operational burden onto the
registry (retry, backoff, dead-letter, SSRF defense, multiplied by
consumer count) while simultaneously demanding every consumer run a
server. SSE asks nothing new of the consumer beyond what it already does
(outbound requests) and asks the registry to hold a socket rather than a
durable commitment to retry indefinitely against arbitrary URLs.

## 5. Comparison table

| Dimension | Polling (current) | SSE | Webhooks |
|---|---|---|---|
| Consumer accepts inbound connections | No | No | Yes, required |
| Registry holds per-consumer state | No | Ephemeral (open socket) | Yes, durable (URL, retry state) |
| Failure/retry complexity | None, next poll retries | Low, client-driven reconnect | High, registry-driven retry, backoff, dead-letter, per-target isolation |
| Works behind NAT / outbound-only firewalls | Yes | Yes | No |
| Latency, publish to notice | Up to one poll interval | Near-immediate | Near-immediate |
| Added dependencies | None | None (axum ships SSE support) | New: URL storage, delivery worker, SSRF defenses |
| Interaction with fail-closed head check | Unaffected, head checked every sync | Unaffected if the event stays a hint | Same requirement, but a compromised or careless implementation could be tempted to attach payload to the POST |
| Attack surface added | None | One more long-lived route, proxy-buffering misconfiguration risk | SSRF against consumer-supplied URLs, registry becomes a request forger |

## 6. The recommendation

If and when push is worth building, build SSE, not webhooks. Keep polling
as the baseline and the default in every case.

This is specific to how this codebase is already shaped, not a generic
preference:

- The consumer side is deliberately a small client with no inbound
  surface. `src/httpclient.rs` says so outright, and the `client` feature
  is split from `server` so a consumer never has to link `axum`. Webhooks
  require every adopter to run an HTTPS listener, inverting this choice for
  every consumer, not just the registry operator.
- The registry is deliberately stateless per consumer. The README calls
  this "the entire point": the cursor lives with the subscriber, which
  makes a restart safe on either side without coordination. Webhooks put a
  callback URL, delivery state, and retry counters into the registry, per
  consumer, exactly the state this project chose not to carry.
- SSE preserves both properties: the consumer still initiates the
  connection and owns its cursor, and the registry loses nothing but
  latency if it forgets a connection, because the next poll is still
  authoritative.

The condition under which this becomes worth doing, so a future reader can
check whether it has been met: a registry serving enough subscribers that
idle poll load shows up in its own metrics or hosting bill, or a consumer
use case that genuinely needs sub-minute propagation (something reacting to
a new registration in near real time, as opposed to a human reviewing and
pinning a new publisher, which is not latency-bound). Until one of those is
true, the 30 second poll interval costs nothing measurable, and a streaming
endpoint, however cheap, is work spent on a problem nobody has yet.

## 7. What would have to be true to implement it

- The event payload carries only a seq hint (and optionally `head_seq`),
  never template content, never a registration body, never anything that
  looks importable on its own.
- On any event the subscriber runs the full verified sync, including the
  feed head check, exactly as `Subscriber::sync` does today. An event is
  never a shortcut past `check_head`.
- A missed, forged, or dropped event is harmless by construction, because
  the next poll is authoritative and reprocesses whatever the cursor has
  not yet seen. Nothing about correctness may depend on an event arriving.
- Polling stays wired in as the fallback and the correctness baseline, not
  a historical option. The `--once` and default-interval behavior in
  `src/bin/subscribe.rs` should not be removed or made conditional on SSE
  availability.
- A subscriber must keep polling periodically even while an SSE connection
  looks healthy. A stream that has silently stopped delivering (a half-open
  TCP connection, a proxy that ate the keep-alives, a leaked connection
  handle) is indistinguishable from "nothing was published." Only an
  underlying poll can catch that a believed-live connection has gone
  stale, which is exactly what makes SSE without a poll fallback strictly
  worse than polling alone: it can be confidently wrong in a way plain
  polling cannot.

## 8. Explicitly out of scope

- Any transport that changes what is verified. Section 2's point is that
  transport and verification are orthogonal; blurring that line (trusting
  an event body because it arrived over a trusted connection)
  reintroduces the registry-can-lie-by-omission problem `src/feedhead.rs`
  was built to close, over a different wire protocol.
- Any push mechanism that would let a registry cause a consumer to import
  something without the normal chain (tree verification, self-certifying
  vendor check, definition rehash against `template_hash`, pin check).
  That chain is the security model in the README's "The verification
  chain," and no latency win from section 1 justifies weakening it.
