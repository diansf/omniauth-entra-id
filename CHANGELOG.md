# Change Log

## v3.1.1 (2025-09-12)

* Validates the JWT `iss` (issuer) claim for `consumers` tenants properly, using the global GUID for that use case, resolving #51 (reported by @2called-chaos)

## v3.1.0 (2025-06-17)

* Provides a way to ignore TID when constructing a user UID, easing migration from v2.x, via the new `ignore_tid` option, resolving #42 (reported by @s-andringa)
* Handles a missing (`nil`) TID, via #46 (thanks to @frenkel)
* Ruby 3.4 "officially" supported through coverage in CI, via #47 (thanks to @hakeem0114)
* Supports JWT gem v2.9.x or v3.x, via #48 (thanks to @djpremier)

## v3.0.1 (2024-11-21)

* Fixes a minor error in [`UPGRADING.md`](UPGRADING.md) reported in #38, via #40 (thanks to @kennethgeerts)
* Fixes incorrect attempt to verify JWT token issuer when the AD FS tenant `adfs` is specified, via #39 (thanks to @washu)

## v3.0.0 (2024-10-22)

* To upgrade from the Azure ActiveDirectory V2 gem, please see [`UPGRADING.md`](UPGRADING.md)
* Branched from `omniauth-azure-activedirectory-v2` version 2.4.0 and renamed to `omniauth-entra-id`
* Can specify `tenant_name` in options via #31 (thanks to @Jureamer) for B2C login
* Supports authenticating with a certificate instead of client secret via #32 (thanks to @juliaducey)
* ID token extraction and validation is improved; long-standing fault with UID generation from OIDs (see #33) addressed via #34 (thanks to @tom-brouwer-bex)
