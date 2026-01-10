// Example: How to use note selector with note storage for withdrawals

import { InMemoryNoteStorage, DepositNote } from "./note-storage";
import {
  selectNotesForWithdrawal,
  selectNotesOptimal,
  getWithdrawalOptions,
  formatAmount,
} from "./note-selector";

/**
 * Example 1: Simple withdrawal
 */
export function simpleWithdrawal() {
  const storage = new InMemoryNoteStorage();

  // Assume you have notes stored from previous deposits
  // storage.save(...) was called after each deposit

  const withdrawAmount = BigInt(2_500_000_000); // 2.5 SOL
  const unspentNotes = storage.getUnspent();

  const result = selectNotesForWithdrawal(unspentNotes, withdrawAmount);

  if (result.success) {
    console.log(`✅ ${result.message}`);
    console.log(`Selected notes:`);
    result.notes.forEach((note, i) => {
      console.log(
        `  Note ${i + 1}: ${formatAmount(note.amount)} (index: ${
          note.leafIndex
        })`
      );
    });
    console.log(`Change: ${formatAmount(result.changeAmount)}`);

    // Use these notes for withdrawal proof generation
    return result.notes;
  } else if (result.needsCombining) {
    console.log(`⚠️  ${result.message}`);
    console.log(`Need to combine notes first:`);
    result.combineStrategy?.steps.forEach((step, i) => {
      console.log(`  Step ${i + 1}: ${step.description}`);
    });
    return null;
  } else {
    console.log(`❌ ${result.message}`);
    return null;
  }
}

/**
 * Example 2: Optimal withdrawal (minimize change)
 */
export function optimalWithdrawal() {
  const storage = new InMemoryNoteStorage();
  const withdrawAmount = BigInt(3_000_000_000); // 3 SOL
  const unspentNotes = storage.getUnspent();

  // Try to minimize change (max 5% change accepted)
  const result = selectNotesOptimal(unspentNotes, withdrawAmount);

  if (result.success) {
    const changePercent = Number((result.changeAmount * 100n) / withdrawAmount);
    console.log(`✅ Found optimal selection`);
    console.log(`   Using ${result.notes.length} note(s)`);
    console.log(
      `   Change: ${formatAmount(result.changeAmount)} (${changePercent.toFixed(
        2
      )}%)`
    );

    return result.notes;
  }

  return null;
}

/**
 * Example 3: Show user all withdrawal options
 */
export function showWithdrawalOptions() {
  const storage = new InMemoryNoteStorage();
  const withdrawAmount = BigInt(5_000_000_000); // 5 SOL
  const unspentNotes = storage.getUnspent();

  const options = getWithdrawalOptions(unspentNotes, withdrawAmount);

  console.log(`\n💰 Withdrawal Options for ${formatAmount(withdrawAmount)}:`);
  console.log(`   Total available: ${formatAmount(options.totalAvailable)}\n`);

  if (options.singleNoteOptions.length > 0) {
    console.log(
      `📝 Single note options (${options.singleNoteOptions.length}):`
    );
    options.singleNoteOptions.slice(0, 3).forEach((opt, i) => {
      console.log(
        `   ${i + 1}. Use ${formatAmount(
          opt.note.amount
        )} note → ${formatAmount(opt.change)} change`
      );
    });
    console.log();
  }

  if (options.twoNoteOptions.length > 0) {
    console.log(`📝 Two note options (${options.twoNoteOptions.length}):`);
    options.twoNoteOptions.slice(0, 3).forEach((opt, i) => {
      const [n1, n2] = opt.notes;
      console.log(
        `   ${i + 1}. Use ${formatAmount(n1.amount)} + ${formatAmount(
          n2.amount
        )} → ${formatAmount(opt.change)} change`
      );
    });
    console.log();
  }

  if (options.needsCombining) {
    console.log(`⚠️  Need to combine notes first`);
    console.log(`   No single note or pair covers the withdrawal amount`);
    console.log(`   Suggestion: Combine smaller notes before withdrawing\n`);
  }

  if (!options.canWithdrawImmediately && !options.needsCombining) {
    console.log(`❌ Insufficient balance\n`);
  }

  return options;
}

/**
 * Example 4: Complete withdrawal workflow
 */
export async function completeWithdrawalWorkflow(
  storage: InMemoryNoteStorage,
  withdrawAmount: bigint,
  generateProofAndWithdraw: (
    notes: DepositNote[],
    amount: bigint,
    change: bigint
  ) => Promise<boolean>
) {
  console.log(`\n🔄 Starting withdrawal for ${formatAmount(withdrawAmount)}`);

  // Step 1: Check balance
  const balance = storage.getBalance();
  console.log(`   Current balance: ${formatAmount(balance)}`);

  if (balance < withdrawAmount) {
    console.log(`   ❌ Insufficient balance`);
    return false;
  }

  // Step 2: Select notes
  const unspentNotes = storage.getUnspent();
  const result = selectNotesForWithdrawal(unspentNotes, withdrawAmount);

  if (!result.success) {
    if (result.needsCombining) {
      console.log(`   ⚠️  Need to combine notes first`);
      // In your wallet, you'd show the combine strategy to user
      // and let them execute combining transactions first
    } else {
      console.log(`   ❌ ${result.message}`);
    }
    return false;
  }

  console.log(`   ✅ Selected ${result.notes.length} note(s)`);
  console.log(`   Total input: ${formatAmount(result.totalAmount)}`);
  console.log(`   Withdraw: ${formatAmount(withdrawAmount)}`);
  console.log(`   Change: ${formatAmount(result.changeAmount)}`);

  // Step 3: Generate proof and submit withdrawal
  console.log(`\n   🔐 Generating ZK proof...`);
  const success = await generateProofAndWithdraw(
    result.notes,
    withdrawAmount,
    result.changeAmount
  );

  if (success) {
    // Step 4: Mark notes as spent
    console.log(`   ✅ Withdrawal successful`);
    result.notes.forEach((note) => {
      const id = Buffer.from(note.commitment).toString("hex").slice(0, 16);
      storage.markSpent(id);
    });

    console.log(`   💾 Marked ${result.notes.length} note(s) as spent`);
    console.log(`   💰 New balance: ${formatAmount(storage.getBalance())}\n`);
    return true;
  }

  console.log(`   ❌ Withdrawal failed\n`);
  return false;
}

/**
 * Example 5: For your wallet extension
 * This is the main function you'd call from your UI
 */
export interface WithdrawalPlan {
  canProceed: boolean;
  selectedNotes: DepositNote[];
  totalInput: bigint;
  withdrawAmount: bigint;
  changeAmount: bigint;
  fee: bigint;
  netToRecipient: bigint;
  needsCombining: boolean;
  combineSteps?: Array<{ notes: DepositNote[]; description: string }>;
  message: string;
}

export function planWithdrawal(
  storage: InMemoryNoteStorage,
  withdrawAmount: bigint,
  feeBps: number = 100 // 1% fee
): WithdrawalPlan {
  const unspentNotes = storage.getUnspent();
  const result = selectNotesForWithdrawal(unspentNotes, withdrawAmount);

  const fee = (withdrawAmount * BigInt(feeBps)) / 10_000n;
  const netToRecipient = withdrawAmount - fee;

  if (result.success) {
    return {
      canProceed: true,
      selectedNotes: result.notes,
      totalInput: result.totalAmount,
      withdrawAmount,
      changeAmount: result.changeAmount,
      fee,
      netToRecipient,
      needsCombining: false,
      message: result.message,
    };
  } else if (result.needsCombining) {
    return {
      canProceed: false,
      selectedNotes: [],
      totalInput: 0n,
      withdrawAmount,
      changeAmount: 0n,
      fee,
      netToRecipient,
      needsCombining: true,
      combineSteps: result.combineStrategy?.steps,
      message: "Need to combine notes first. See combineSteps for the plan.",
    };
  } else {
    return {
      canProceed: false,
      selectedNotes: [],
      totalInput: 0n,
      withdrawAmount,
      changeAmount: 0n,
      fee,
      netToRecipient,
      needsCombining: false,
      message: result.message,
    };
  }
}
