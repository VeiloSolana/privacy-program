# Phoenix Limit Order with Conditionals — Implementation Guide

> Verified against Rise SDK source: `/tmp/rise-public/rust/ix/src/conditional_order.rs`,
> `order_packet.rs`, `types.rs`, and `constants.rs`.

## The Problem

`place_position_conditional_order` attaches TP/SL to an **existing filled position**.
When a PostOnly (resting limit) order is placed, no position exists yet — so calling it
immediately fails with:

> "Conditional order must be in opposite direction of trader position"

## The Correct Instruction: `place_limit_order_with_conditionals`

Phoenix Eternal exposes `place_limit_order_with_conditionals`, which atomically places a
resting limit order AND attaches TP/SL to it in one instruction. The TP/SL are "children"
of the parent limit order:

- While the limit order is resting, TP/SL share its size.
- When the parent fully fills → TP/SL become independent conditional orders.
- If the parent is cancelled → attached TP/SL cancel too.

---

## Discriminator

```
sha256("global:place_limit_order_with_conditionals")[0..8]
```

Computed identically to all other Phoenix discriminators (confirmed in `constants.rs` line 234).

---

## Instruction Data Layout

All fields Borsh-serialized in this order (from `PlaceLimitOrderWithConditionalsData`):

```
[0..8]   discriminator               — 8 bytes
[8..46]  order_packet (PostOnly)     — 38 bytes (Borsh of OrderPacketKind::PostOnly)
[46..54] slot                        — u64 LE (pass 0; only used for expiry)
[54]     greater_trigger_order       — Option<TriggerOrderParams>: 0x00=None, 0x01+19bytes=Some
[...]    less_trigger_order          — Option<TriggerOrderParams>: 0x00=None, 0x01+19bytes=Some
```

### Order Packet Bytes (38 bytes, PostOnly variant)

The `order_packet` field is the **raw Borsh bytes of `OrderPacketKind`** — exactly
what you get from `encodePostOnlyLimitOrder` after stripping its 8-byte Veilo disc prefix.

**`OrderPacketKind` enum discriminants** (confirmed from SDK tests):
- `PostOnly = 0` ← use this for resting limit orders
- `Limit = 1` — can cross the book; not used here
- `ImmediateOrCancel = 2`

PostOnly Borsh layout (38 bytes):
```
[0]      variant          — u8: 0 (PostOnly)
[1]      side             — u8: 0=Bid, 1=Ask
[2..10]  price_in_ticks   — u64 LE
[10..18] num_base_lots    — u64 LE
[18..34] client_order_id  — [u8; 16], all zeros is fine
[34]     slide            — bool: 1 = auto-slide if crossing
[35]     last_valid_slot  — 0x00 = None
[36]     order_flags      — u8: 0
[37]     cancel_existing  — bool: 0
```

This matches `encodePostOnlyLimitOrder` exactly (variant byte 0 at offset 8 of the
full 46-byte buffer is the packet start after the Veilo disc).

### TriggerOrderParams (19 bytes, from `types.rs`)

```
[0]      trigger_direction — u8: Direction enum
[1]      trade_side        — u8: Side enum
[2]      order_kind        — u8: StopLossOrderKind enum
[3..11]  trigger_price     — u64 LE (in Phoenix ticks)
[11..19] execution_price   — u64 LE (in Phoenix ticks; set equal to trigger_price)
```

**Direction enum** (`direction` field):
- `GreaterThan = 0` — for `greater_trigger_order` (TP for longs, SL for shorts)
- `LessThan = 1` — for `less_trigger_order` (SL for longs, TP for shorts)

The SDK validates this: `greater_trigger_order` **must** have `GreaterThan`,
`less_trigger_order` **must** have `LessThan`.

**StopLossOrderKind enum** (`order_kind` field):
- `IOC = 0` — immediate-or-cancel (market-like, guaranteed execution) ← use this
- `Limit = 1` — resting limit at execution_price

**Key TP/SL parameters by position direction:**

| Limit order opens | Close side | TP: direction / trade_side | SL: direction / trade_side |
|-------------------|------------|----------------------------|----------------------------|
| Long (Bid, side=0) | Ask (1) | GreaterThan (0) / Ask (1) | LessThan (1) / Ask (1) |
| Short (Ask, side=1) | Bid (0) | LessThan (1) / Bid (0) | GreaterThan (0) / Bid (0) |

Note: both TP and SL always use the same `trade_side` (the closing side), regardless
of which leg fires.

---

## Account Layout

From `create_place_limit_order_with_conditionals_ix` (lines 798–815 of `conditional_order.rs`).
Fixed accounts with **one** globalTraderIndex and **one** activeTraderBuffer:

```
[0]  phoenixProgram          — readonly      (EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih)
[1]  logAuthority            — readonly      (PHOENIX_LOG_AUTHORITY constant)
[2]  globalConfiguration     — WRITABLE      (2zskx2iyCvb6Stg7RBZkt1f6MrF4dpYtMG3yMvKwqtUZ)
[3]  traderWallet            — readonly, signer   (executor PDA — signs via PDA)
[4]  traderAccount           — writable      (DynamicTrader PDA)
[5]  perpAssetMap            — writable
[6]  globalTraderIndex[0]    — writable      (variable length; one per arena)
[7]  activeTraderBuffer[0]   — writable      (variable length; one per arena)
[8]  orderbook               — writable
[9]  splineCollection        — writable
[10] payer                   — writable, signer   (relayer keypair)
[11] traderConditionalOrders — writable      (PDA: seeds=["conditional_orders", traderAccount])
[12] systemProgram           — readonly
```

**Critical differences vs `place_position_conditional_order`:**

| Account | `place_position_conditional_order` | `place_limit_order_with_conditionals` |
|---------|-------------------------------------|---------------------------------------|
| globalConfiguration | readonly | **writable** |
| traderWallet position | after splineCollection [10] | before traderAccount [3] |
| payer position | before traderAccount [3] | after splineCollection [10] |

---

## Comparison: existing Veilo `phoenix_place_position_conditional_order` accounts

Shown for reference (from `phoenix.rs` lines 2050–2063):
```
[0]  phoenixProgram          — readonly
[1]  logAuthority            — readonly
[2]  globalConfiguration     — readonly  ← readonly here
[3]  payer (relayer)         — writable, signer  ← payer first
[4]  traderAccount           — writable
[5]  perpAssetMap            — writable
[6]  globalTraderIndex       — writable
[7]  activeTraderBuffer      — writable
[8]  orderbook               — writable
[9]  splineCollection        — writable
[10] executor (traderWallet) — readonly, signer  ← executor last
[11] traderConditionalOrders — writable
[12] systemProgram           — readonly
```

---

## What Needs to Be Built

### 1. On-Chain Rust Instruction (`privacy-program/programs/privacy-pool/src/phoenix.rs`)

Add a new public function `phoenix_place_limit_order_with_conditionals`:

```rust
pub fn phoenix_place_limit_order_with_conditionals<'info>(
    ctx: Context<'_, '_, 'info, 'info, crate::PhoenixPlaceLimitOrderWithConditionals<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    order_packet_bytes: Vec<u8>,    // raw 38-byte PostOnly Borsh bytes (no disc prefix)
    slot: u64,                       // pass 0 from server
    // TP (greater) — fires when price RISES above trigger
    has_greater: bool,
    greater_trigger_price: u64,
    greater_execution_price: u64,
    greater_trade_side: u8,
    greater_order_kind: u8,          // 0=IOC recommended
    // SL (less) — fires when price FALLS below trigger
    has_less: bool,
    less_trigger_price: u64,
    less_execution_price: u64,
    less_trade_side: u8,
    less_order_kind: u8,             // 0=IOC recommended
) -> Result<()>
```

**Remaining accounts layout** (13 accounts for single-arena markets):
```
[0]  phoenixProgram          — readonly
[1]  logAuthority            — readonly
[2]  globalConfiguration     — writable  ← note: writable, unlike place_position_conditional
[3]  traderAccount           — writable
[4]  perpAssetMap            — writable
[5]  globalTraderIndex       — writable
[6]  activeTraderBuffer      — writable
[7]  orderbook               — writable
[8]  splineCollection        — writable
[9]  traderConditionalOrders — writable
[10] systemProgram           — readonly
```

`executor` (traderWallet, [3] in Phoenix) and `relayer` (payer, [10] in Phoenix) come
from the Veilo instruction's named accounts — they're NOT in remaining_accounts.

**Data building:**
```rust
let disc = phoenix_disc("place_limit_order_with_conditionals");
let mut data = Vec::new();
data.extend_from_slice(&disc);
data.extend_from_slice(&order_packet_bytes);          // 38 raw bytes
data.extend_from_slice(&slot.to_le_bytes());           // u64 LE

// greater_trigger_order: Option<TriggerOrderParams>
if has_greater {
    data.push(0x01);
    data.extend_from_slice(&encode_trigger(
        0,  // Direction::GreaterThan
        greater_trade_side, greater_order_kind,
        greater_trigger_price, greater_execution_price
    ));
} else {
    data.push(0x00);
}

// less_trigger_order: Option<TriggerOrderParams>
if has_less {
    data.push(0x01);
    data.extend_from_slice(&encode_trigger(
        1,  // Direction::LessThan
        less_trade_side, less_order_kind,
        less_trigger_price, less_execution_price
    ));
} else {
    data.push(0x00);
}
```

**Account metas** (passed to Phoenix):
```rust
let account_metas = vec![
    AccountMeta::new_readonly(remaining[0].key(), false), // phoenixProgram
    AccountMeta::new_readonly(remaining[1].key(), false), // logAuthority
    AccountMeta::new(remaining[2].key(), false),          // globalConfiguration (writable!)
    AccountMeta::new_readonly(executor_key, true),        // traderWallet (executor, readonly signer)
    AccountMeta::new(remaining[3].key(), false),          // traderAccount
    AccountMeta::new(remaining[4].key(), false),          // perpAssetMap
    AccountMeta::new(remaining[5].key(), false),          // globalTraderIndex
    AccountMeta::new(remaining[6].key(), false),          // activeTraderBuffer
    AccountMeta::new(remaining[7].key(), false),          // orderbook
    AccountMeta::new(remaining[8].key(), false),          // splineCollection
    AccountMeta::new(ctx.accounts.relayer.key(), true),   // payer (relayer, writable signer)
    AccountMeta::new(remaining[9].key(), false),          // traderConditionalOrders
    AccountMeta::new_readonly(remaining[10].key(), false), // systemProgram
];
```

Account struct `PhoenixPlaceLimitOrderWithConditionals` in `lib.rs` mirrors
`PhoenixPlacePositionConditionalOrder` (same named accounts: `config`, `relayer`,
`executor`).

### 2. Register in `lib.rs`

```rust
pub fn phoenix_place_limit_order_with_conditionals<'info>(
    ctx: Context<'_, '_, 'info, 'info, PhoenixPlaceLimitOrderWithConditionals<'info>>,
    mint_address: Pubkey,
    claimant: Pubkey,
    order_packet_bytes: Vec<u8>,
    slot: u64,
    has_greater: bool,
    greater_trigger_price: u64,
    greater_execution_price: u64,
    greater_trade_side: u8,
    greater_order_kind: u8,
    has_less: bool,
    less_trigger_price: u64,
    less_execution_price: u64,
    less_trade_side: u8,
    less_order_kind: u8,
) -> Result<()> {
    phoenix::phoenix_place_limit_order_with_conditionals(ctx, mint_address, claimant,
        order_packet_bytes, slot,
        has_greater, greater_trigger_price, greater_execution_price,
        greater_trade_side, greater_order_kind,
        has_less, less_trigger_price, less_execution_price,
        less_trade_side, less_order_kind)
}
```

### 3. Relayer Server (`phoenix.controller.ts`)

In the PostOnly skip block (where `variant === 0` and TP/SL exist):

- Strip the 8-byte Veilo disc prefix from `orderDataRaw` to get the 38-byte packet bytes
- `closeSide` = opposite of order side (Bid limit → Ask close = 1; Ask limit → Bid close = 0)
- TP is the `greater` leg (Direction::GreaterThan = 0)
- SL is the `less` leg (Direction::LessThan = 1)
- Pass `order_kind = 0` (IOC) for both legs for guaranteed execution

The remaining_accounts passed as Veilo instruction accounts (in the server's tx builder)
must follow the 11-slot layout above.

### 4. Client (`wallet-app`)

Revert the `PerpsOrderModal.tsx` changes that disabled TP/SL for limit orders. The correct
behavior is TP/SL always available for both order types. Remove `isOpposingExistingPos`
guard from `swap.tsx` once the Rust instruction is live.

---

## Rollout Checklist

- [ ] Add `phoenix_place_limit_order_with_conditionals` to `phoenix.rs`
- [ ] Add `PhoenixPlaceLimitOrderWithConditionals` account struct to `lib.rs`
- [ ] Register the instruction in `lib.rs`
- [ ] Build + deploy updated program (requires upgrade authority)
- [ ] Update relayer server — use new instruction for PostOnly + TP/SL instead of skipping
- [ ] Revert `PerpsOrderModal.tsx` TP/SL disable changes
- [ ] Remove `isOpposingExistingPos` guard from `swap.tsx`

Current status: Steps 1–3 blocked pending program upgrade authority. Stopgap: server skips
TP/SL for PostOnly orders (they succeed without bracket). Steps 5–7 after deploy.
