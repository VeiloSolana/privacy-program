// Note selection utilities for withdrawals
// Handles the 2-in-2-out circuit constraint

import { DepositNote } from './note-storage';

export interface NoteSelectionResult {
  success: boolean;
  notes: DepositNote[];
  totalAmount: bigint;
  changeAmount: bigint;
  message: string;
  needsCombining?: boolean; // If true, user should combine notes first
  combineStrategy?: CombineStrategy;
}

export interface CombineStrategy {
  steps: Array<{
    notes: DepositNote[];
    description: string;
  }>;
  finalWithdrawal: {
    notes: DepositNote[];
    description: string;
  };
}

/**
 * Select notes for a withdrawal amount
 * Handles the 2-in-2-out circuit constraint
 * 
 * @param availableNotes - All unspent notes
 * @param withdrawAmount - Amount to withdraw (in lamports)
 * @param minChangeAmount - Minimum change to keep as new note (default: 0.01 SOL)
 * @returns Selection result with notes to use
 */
export function selectNotesForWithdrawal(
  availableNotes: DepositNote[],
  withdrawAmount: bigint,
  minChangeAmount: bigint = BigInt(10_000_000) // 0.01 SOL
): NoteSelectionResult {
  
  // Sort notes by amount (largest first) for better selection
  const notes = [...availableNotes].sort((a, b) => 
    Number(b.amount - a.amount)
  );

  if (notes.length === 0) {
    return {
      success: false,
      notes: [],
      totalAmount: 0n,
      changeAmount: 0n,
      message: 'No notes available',
    };
  }

  const totalBalance = notes.reduce((sum, n) => sum + n.amount, 0n);
  
  if (totalBalance < withdrawAmount) {
    return {
      success: false,
      notes: [],
      totalAmount: totalBalance,
      changeAmount: 0n,
      message: `Insufficient balance. Have: ${totalBalance}, need: ${withdrawAmount}`,
    };
  }

  // Strategy 1: Single note covers the withdrawal
  const singleNote = notes.find(n => n.amount >= withdrawAmount);
  if (singleNote) {
    const change = singleNote.amount - withdrawAmount;
    return {
      success: true,
      notes: [singleNote],
      totalAmount: singleNote.amount,
      changeAmount: change,
      message: `Using 1 note (${singleNote.amount} lamports). Change: ${change} lamports`,
    };
  }

  // Strategy 2: Find 2 notes that cover the withdrawal
  for (let i = 0; i < notes.length; i++) {
    for (let j = i + 1; j < notes.length; j++) {
      const combined = notes[i].amount + notes[j].amount;
      if (combined >= withdrawAmount) {
        const change = combined - withdrawAmount;
        return {
          success: true,
          notes: [notes[i], notes[j]],
          totalAmount: combined,
          changeAmount: change,
          message: `Using 2 notes (${notes[i].amount} + ${notes[j].amount} = ${combined} lamports). Change: ${change} lamports`,
        };
      }
    }
  }

  // Strategy 3: Need to combine notes first (3+ notes required)
  const combineStrategy = planCombineStrategy(notes, withdrawAmount);
  
  return {
    success: false,
    notes: [],
    totalAmount: totalBalance,
    changeAmount: 0n,
    message: `Need to combine notes first. No single note or pair covers ${withdrawAmount} lamports`,
    needsCombining: true,
    combineStrategy,
  };
}

/**
 * Find the optimal combination strategy for multiple notes
 * Minimizes the number of combining transactions needed
 */
function planCombineStrategy(
  notes: DepositNote[],
  withdrawAmount: bigint
): CombineStrategy {
  const steps: Array<{ notes: DepositNote[]; description: string }> = [];
  
  // Sort by amount
  const sorted = [...notes].sort((a, b) => Number(b.amount - a.amount));
  
  // Greedy approach: combine smallest notes first
  let remaining = [...sorted];
  let intermediateNotes: Array<{ amount: bigint; description: string }> = [];
  
  while (remaining.length > 2) {
    // Take the two smallest notes
    const note1 = remaining.pop()!;
    const note2 = remaining.pop()!;
    const combined = note1.amount + note2.amount;
    
    steps.push({
      notes: [note1, note2],
      description: `Combine ${note1.amount} + ${note2.amount} = ${combined} lamports`,
    });
    
    // Add combined note back to pool
    intermediateNotes.push({
      amount: combined,
      description: `Combined note ${steps.length}`,
    });
    
    // Re-sort remaining notes
    remaining.sort((a, b) => Number(b.amount - a.amount));
    
    // Insert intermediate note in sorted position
    const insertIndex = remaining.findIndex(n => n.amount < combined);
    if (insertIndex === -1) {
      // Add pseudo-note representation (in practice, this would be a real note after transaction)
      remaining.push({ amount: combined } as any);
    } else {
      remaining.splice(insertIndex, 0, { amount: combined } as any);
    }
  }
  
  return {
    steps,
    finalWithdrawal: {
      notes: remaining.slice(0, 2) as DepositNote[],
      description: `Finally withdraw using the ${remaining.length <= 2 ? 'combined notes' : 'largest notes'}`,
    },
  };
}

/**
 * Select the best notes to minimize change
 * Tries to find exact or close-to-exact matches
 */
export function selectNotesOptimal(
  availableNotes: DepositNote[],
  withdrawAmount: bigint,
  maxChangePercent: number = 10 // Maximum 10% change
): NoteSelectionResult {
  
  const basicResult = selectNotesForWithdrawal(availableNotes, withdrawAmount);
  
  if (!basicResult.success || basicResult.needsCombining) {
    return basicResult;
  }
  
  // Check if change is acceptable
  const changePercent = Number(basicResult.changeAmount * 100n / withdrawAmount);
  
  if (changePercent <= maxChangePercent) {
    return basicResult;
  }
  
  // Try to find better combination with less change
  const notes = [...availableNotes].sort((a, b) => 
    Number(b.amount - a.amount)
  );
  
  let bestResult = basicResult;
  let lowestChange = basicResult.changeAmount;
  
  // Check all pairs
  for (let i = 0; i < notes.length; i++) {
    // Single note
    if (notes[i].amount >= withdrawAmount) {
      const change = notes[i].amount - withdrawAmount;
      if (change < lowestChange) {
        lowestChange = change;
        bestResult = {
          success: true,
          notes: [notes[i]],
          totalAmount: notes[i].amount,
          changeAmount: change,
          message: `Optimal: 1 note with ${change} lamports change (${Number(change * 100n / withdrawAmount)}%)`,
        };
      }
    }
    
    // Pairs
    for (let j = i + 1; j < notes.length; j++) {
      const combined = notes[i].amount + notes[j].amount;
      if (combined >= withdrawAmount) {
        const change = combined - withdrawAmount;
        if (change < lowestChange) {
          lowestChange = change;
          bestResult = {
            success: true,
            notes: [notes[i], notes[j]],
            totalAmount: combined,
            changeAmount: change,
            message: `Optimal: 2 notes with ${change} lamports change (${Number(change * 100n / withdrawAmount)}%)`,
          };
        }
      }
    }
  }
  
  return bestResult;
}

/**
 * Get a summary of available withdrawal options
 * Useful for showing user their options
 */
export function getWithdrawalOptions(
  availableNotes: DepositNote[],
  withdrawAmount: bigint
): {
  canWithdrawImmediately: boolean;
  singleNoteOptions: Array<{ note: DepositNote; change: bigint }>;
  twoNoteOptions: Array<{ notes: [DepositNote, DepositNote]; change: bigint }>;
  needsCombining: boolean;
  totalAvailable: bigint;
} {
  
  const totalAvailable = availableNotes.reduce((sum, n) => sum + n.amount, 0n);
  const singleNoteOptions: Array<{ note: DepositNote; change: bigint }> = [];
  const twoNoteOptions: Array<{ notes: [DepositNote, DepositNote]; change: bigint }> = [];
  
  // Find single note options
  for (const note of availableNotes) {
    if (note.amount >= withdrawAmount) {
      singleNoteOptions.push({
        note,
        change: note.amount - withdrawAmount,
      });
    }
  }
  
  // Find two note options
  for (let i = 0; i < availableNotes.length; i++) {
    for (let j = i + 1; j < availableNotes.length; j++) {
      const combined = availableNotes[i].amount + availableNotes[j].amount;
      if (combined >= withdrawAmount) {
        twoNoteOptions.push({
          notes: [availableNotes[i], availableNotes[j]],
          change: combined - withdrawAmount,
        });
      }
    }
  }
  
  // Sort by least change
  singleNoteOptions.sort((a, b) => Number(a.change - b.change));
  twoNoteOptions.sort((a, b) => Number(a.change - b.change));
  
  return {
    canWithdrawImmediately: singleNoteOptions.length > 0 || twoNoteOptions.length > 0,
    singleNoteOptions,
    twoNoteOptions,
    needsCombining: singleNoteOptions.length === 0 && twoNoteOptions.length === 0 && totalAvailable >= withdrawAmount,
    totalAvailable,
  };
}

/**
 * Format amount for display (lamports to SOL)
 */
export function formatAmount(lamports: bigint): string {
  const sol = Number(lamports) / 1_000_000_000;
  return `${sol.toFixed(9)} SOL`;
}

/**
 * Example usage
 */
export function exampleUsage() {
  // Mock notes
  const notes: DepositNote[] = [
    { amount: BigInt(1_000_000_000), leafIndex: 0 } as DepositNote, // 1 SOL
    { amount: BigInt(2_000_000_000), leafIndex: 1 } as DepositNote, // 2 SOL
    { amount: BigInt(500_000_000), leafIndex: 2 } as DepositNote,   // 0.5 SOL
  ];
  
  const withdrawAmount = BigInt(2_500_000_000); // 2.5 SOL
  
  // Basic selection
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  console.log(result.message);
  
  if (result.success) {
    console.log(`Selected ${result.notes.length} note(s)`);
    console.log(`Total: ${formatAmount(result.totalAmount)}`);
    console.log(`Change: ${formatAmount(result.changeAmount)}`);
  } else if (result.needsCombining) {
    console.log('Need to combine notes first:');
    result.combineStrategy?.steps.forEach((step, i) => {
      console.log(`  Step ${i + 1}: ${step.description}`);
    });
  }
  
  // Optimal selection (minimize change)
  const optimal = selectNotesOptimal(notes, withdrawAmount);
  console.log(`\nOptimal: ${optimal.message}`);
  
  // Get all options
  const options = getWithdrawalOptions(notes, withdrawAmount);
  console.log(`\nCan withdraw immediately: ${options.canWithdrawImmediately}`);
  console.log(`Single note options: ${options.singleNoteOptions.length}`);
  console.log(`Two note options: ${options.twoNoteOptions.length}`);
}
