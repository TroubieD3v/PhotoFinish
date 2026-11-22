/**
 * The commented starting point of "New scenario": a runnable scenario
 * against the demo shop. Lines stay within 56 characters, so that the
 * editor shows them whole next to the side panel at 1024 px.
 */
export const NEW_SCENARIO = `# A scenario describes one race: requests sent
# together, and a rule (the invariant) that must still
# hold afterwards. This one runs against the demo shop;
# start it from the sidebar first.
#
# Only test systems you are authorized to test:
# requests go only to the hosts in scope.allow_hosts,
# and scope.budget caps how many are sent.
version: 1
name: my-scenario
description: >
  WELCOME10 is a single-use coupon. Applying it many
  times at once must still leave one discount on the
  cart.

# Base URL; request paths below are relative to it.
target: https://127.0.0.1:8443/vuln/api
tls:
  # The demo shop uses a self-signed certificate.
  insecure: true

scope:
  allow_hosts: [127.0.0.1:8443]
  budget: { requests: 1000, rps: 50 }

# Headers per identity. Read real credentials from the
# environment:
#   Authorization: "Bearer \${env:ALICE_TOKEN}"
identities:
  alice:
    headers: { Authorization: "Bearer demo-alice" }

vars: { code: WELCOME10 }

# Runs before every trial; extract keeps values for
# later steps.
setup:
  - id: reset
    request: POST /reset
    expect_status: [200]
  - id: cart
    as: alice
    request: POST /carts
    expect_status: [201]
    extract: { cart_id: "$.id" }

# The race: copies of one request released together.
race:
  # auto: h2 single-packet when the server speaks
  # HTTP/2, else h1 last-byte.
  engine: auto
  copies: 20
  request:
    as: alice
    raw: |
      POST /carts/{{cart_id}}/coupons HTTP/2
      Content-Type: application/json

      {"code":"{{code}}"}

# After the race: one request, then the invariant in
# CEL over check (that response), race (all race
# responses), setup and vars.
check:
  as: alice
  request: GET /carts/{{cart_id}}
  invariant: >
    size(check.json.discounts) <= 1 &&
    size(race.filter(r, r.status == 200)) <= 1
  explain: >
    A single-use coupon must apply at most once per
    cart.

trials: 10
`;
