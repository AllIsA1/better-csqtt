# Better CSQTT

A plugin for the [LucX-UI](https://github.com/AlexeyLCP/lucx-ui) plugin system: **one CSQTT password per person**.

## Why

The CSQTT server lets one password hold one live session: when a second device connects with the same password, it takes the
session over from the first (the server's `PasswordEpochDecision::Replaced`). The panel gives every subscription the same shared
password, so two people on one CSQTT inbound push each other off.

The CSQTT server also keeps a list of *members*: each has a password of its own, its own tunnel address and its own limits, and can
be made through the server's web API. This plugin uses that list.

## What it does

- For every client of the CSQTT inbound the plugin makes a member named after the client's email, with the inbound's VK hashes, and
  gives that client **their own link** in the subscription (and on the subscription page) in place of the shared one. The name the
  line had is kept.
- A client that is switched off, expired or out of traffic is switched off on the server too, and back on when the panel allows it.
- A client taken off the inbound loses the member. Only members the plugin made are ever switched or deleted: one made by hand, even
  with a client's name, is used for its link and never touched.
- Anything that goes wrong (the server is down, the panel does not answer, no member yet) leaves the subscription as the panel makes
  it, with the shared link. Switch the plugin off and the shared link is back for everybody.
- The plugin has no page of its own and no sidebar entry: it works by itself. Its log shows the members it made.

## How it reaches the server

It reads the CSQTT inbound from the panel (`api:inbounds:read`: its shared password, web password, public host and VK hashes) and the
clients attached to it (`api:clients:read`), and calls the server's web API at `https://<host>:46002` with the web password as
`x-api-key`: on this machine for an inbound of this panel, at the inbound's public host for one on a node (the web port must be
reachable from the master). That is why it holds `network`. The plugin runs on the panel that serves the subscriptions.

## What it does not do

It does not count traffic per member in the panel, and it does not move people between hash sets. A client that is not yet a member
(a new one) gets the shared link until the next check, at most half a minute.

MIT, see `LICENSE`.

## Links in the subscription

The server makes sealed links (`csqtt://<base64url>`); the official CSQTT app reads only those, but it never fetches a subscription.
Proxy clients that do (YPtun, for one) read only the plain form, `csqtt://connect?v=2&host=…&peer=…&password=…&hashes=a+b`. So the raw
subscription carries the member's link in the plain form, with no `#name`; the subscription page keeps the sealed
link for pasting into the official app.
