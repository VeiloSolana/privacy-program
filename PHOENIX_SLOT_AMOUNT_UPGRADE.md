# Phoenix Slot Amount Upgrade — Plan & Guide

## Problem

When a user trades and accumulates profit inside Phoenix, their executor's
`quoteLotCollateral` grows beyond their original deposit. Example:

- Deposited: $10.00 → `slot.amount = 10_000_000`
- After trading: Phoenix collateral = $10.782155
- Exit amount capped to: $10.00 (slot.amount cap)
- Remaining stuck in Phoenix: $0.782155

The Veilo on-chain program enforces `new_withdrawn <= slot.amount` in
`phoenix_queue_withdraw`. Since `slot.amount` is set at deposit time and never
updated, profits above the original deposit cannot be withdrawn.

---

## Solution: Add `max_slot_amount` to `phoenix_queue_withdraw`

### Design

Add an optional parameter `max_slot_amount: Option<u64>` to the existing
`phoenix_queue_withdraw` instruction. Before the cap check, if
`max_slot_amount > slot.amount`, bump `slot.amount` to `max_slot_amount`.

**Why this is safe:**

The Veilo program allows the bump because Phoenix itself is the ultimate
enforcer. If the relayer passes a `max_slot_amount` that exceeds the actual
Phoenix collateral, the `withdraw_funds` CPI will fail on Phoenix's side and
the entire transaction reverts. No money can be created — only the
on-chain Phoenix balance caps the real withdrawal. The Veilo slot.amount
becomes a tracking field that mirrors reality rather than a hard gate.

**No new accounts needed.** The `traderAccount` (already at `remaining[3]`)
holds the actual collateral, but we don't need to parse it on-chain. The server
reads `quoteLotCollateral` from it off-chain (already logged) and passes it in.

---

## Change 1: Rust (`phoenix_queue_withdraw`)

**File:** `privacy-program/programs/privacy-pool/src/phoenix.rs`

**Function signature change:**
```rust
// Before
pub fn phoenix_queue_withdraw<'info>(
    ctx: ...,
    mint_address: Pubkey,
    claimant: Pubkey,
    amount: u64,
    _withdrawal_id: [u8; 32]
) -> Result<()>

// After
pub fn phoenix_queue_withdraw<'info>(
    ctx: ...,
    mint_address: Pubkey,
    claimant: Pubkey,
    amount: u64,
    _withdrawal_id: [u8; 32],
    max_slot_amount: Option<u64>,   // ← new optional parameter
) -> Result<()>
```

**Logic to insert inside the `{ slot cap enforcement }` block, before the cap check:**
```rust
// If caller provides a higher slot cap (e.g. because collateral grew via PnL),
// bump slot.amount before the cap check. Phoenix's withdraw_funds CPI is the
// real safety net — it will reject any amount that exceeds actual collateral.
if let Some(max) = max_slot_amount {
    if max > slot.amount {
        slot.amount = max;  // bump before writing updated slot below
    }
}
// existing: require!(new_withdrawn <= slot.amount, PrivacyError::SlotOverdraft);
```

The `updated` struct write at the end of the block already persists `slot.amount`,
so no additional write is needed.

**lib.rs:** Update the dispatch call to forward the new parameter:
```rust
pub fn phoenix_queue_withdraw<'info>(
    ctx: ...,
    mint_address: Pubkey,
    claimant: Pubkey,
    amount: u64,
    withdrawal_id: [u8; 32],
    max_slot_amount: Option<u64>,
) -> Result<()> {
    phoenix::phoenix_queue_withdraw(ctx, mint_address, claimant, amount, withdrawal_id, max_slot_amount)
}
```

---

## Change 2: Relayer Server (`phoenix.controller.ts`)

**File:** `relayer-server/src/controllers/phoenix.controller.ts`

In `handlePhoenixExit`, before building the queue-withdraw instruction:

1. Read the executor's actual Phoenix collateral from `traderAccount` (already fetched
   for the `slotInfoForWithdrawn` check — this is `remaining[3]` in the on-chain call).
   The server already reads positions and logs `quoteLotCollateralUsd` — expose
   `quoteLotCollateral` (raw u64, in quote lots) for this comparison.

2. Pass `maxSlotAmount` to the Veilo instruction when `actualCollateral > slotDepositCap`:

```typescript
// After reading slotDepositCap from the slot PDA:
let maxSlotAmount: bigint | null = null;

// Read the actual Phoenix collateral from the traderAccount
const traderInfo = await connection.getAccountInfo(traderPda, "confirmed");
const actualCollateral = traderInfo
  ? decodePhoenixCollateralLots(Buffer.from(traderInfo.data))  // new helper, see below
  : null;

if (actualCollateral != null && actualCollateral > slotDepositCap) {
  maxSlotAmount = actualCollateral;
  logger.info(
    `[Phoenix exit] Surplus collateral detected — bumping slot cap ${slotDepositCap} → ${maxSlotAmount}`,
    { symbol }
  );
}

// Then clamp queueAmount to min(actualCollateral, requested):
// (server still caps to the actual balance so Phoenix doesn't reject)
if (slotDepositCap > 0n && slotDepositCap < queueAmount && !maxSlotAmount) {
  queueAmount = slotDepositCap;
}
if (maxSlotAmount != null && maxSlotAmount < queueAmount) {
  queueAmount = maxSlotAmount;
}
```

3. When building the Anchor instruction data for `phoenix_queue_withdraw`, serialize
   `max_slot_amount` as a Borsh `Option<u64>`:
   - `None` → `[0x00]` (1 byte)
   - `Some(n)` → `[0x01, n_le_bytes (8 bytes)]` (9 bytes)

**New helper — `decodePhoenixCollateralLots`:**

The Phoenix `traderAccount` (DynamicTrader) stores `quoteLotCollateral` at a known
offset. From the TypeScript positions decoder (`positionsDecoder.ts`) we already
parse this — extract that field into a standalone helper so `phoenix.controller.ts`
can use it without importing the full positions decoder.

```typescript
// Returns quoteLotCollateral in raw lots (1 lot = 10^-6 USDC)
function decodePhoenixCollateralLots(data: Buffer): bigint | null {
  // DynamicTrader layout (Phoenix Eternal):
  // [0..8]   disc
  // [8..N]   header fields including quoteLotCollateral
  // exact offset: reuse COLLATERAL_OFFSET constant from positionsDecoder.ts
  const OFFSET = ...; // confirm from positionsDecoder.ts
  if (data.length < OFFSET + 8) return null;
  return data.readBigInt64LE(OFFSET);
}
```

> **Before implementing:** confirm the exact byte offset of `quoteLotCollateral`
> in `positionsDecoder.ts` — it's already parsed there.

---

## Rollout Checklist

- [ ] **Rust change** — modify `phoenix_queue_withdraw` signature + slot bump logic
- [ ] **lib.rs** — update dispatch to forward `max_slot_amount`
- [ ] **Build + deploy** program upgrade (requires upgrade authority)
- [ ] **Server** — add `decodePhoenixCollateralLots` helper
- [ ] **Server** — read actual collateral in `handlePhoenixExit` before building ix
- [ ] **Server** — pass `maxSlotAmount` in instruction data (Borsh Option<u64>)
- [ ] **Test** — deposit, trade to make profit, exit: verify full collateral is returned

---

## Backward Compatibility

- Existing callers that don't pass `max_slot_amount` pass `None` → behavior is identical to current
- No account layout changes
- No new PDAs or accounts
- Server change is purely additive (only activates when `actualCollateral > slotDepositCap`)
