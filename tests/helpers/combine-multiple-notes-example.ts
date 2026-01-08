// Example: How to use the new combineMultipleNotes and combineToTwoNotes functions
// This demonstrates combining X notes automatically

// Mock helper functions (replace with your actual implementations)
interface Note {
  amount: bigint;
  commitment: Uint8Array;
  privateKey: Uint8Array;
  publicKey: bigint;
  blinding: Uint8Array;
  leafIndex: number;
}

/**
 * USAGE EXAMPLE 1: Combine X notes into 1 note
 *
 * Use case: User has many small notes and wants to consolidate them
 */
async function exampleCombineToOne() {
  // Assume you have 5 notes from previous deposits
  const notes: Note[] = [
    // ... your 5 notes
  ];

  // This will automatically:
  // 1. Combine note1 + note2 = temp1
  // 2. Combine temp1 + note3 = temp2
  // 3. Combine temp2 + note4 = temp3
  // 4. Combine temp3 + note5 = finalNote
  // Result: 1 note with total amount

  const finalNote = await combineMultipleNotes(notes, "Consolidate all notes");

  console.log(`Combined ${notes.length} notes into 1 note`);
  console.log(`Final amount: ${finalNote.amount}`);

  return finalNote;
}

/**
 * USAGE EXAMPLE 2: Combine X notes into 2 notes (optimal for withdrawal)
 *
 * Use case: User wants to withdraw, needs exactly 2 notes
 */
async function exampleCombineToTwo() {
  // Assume you have 7 notes
  const notes: Note[] = [
    // ... your 7 notes
  ];

  // This will automatically:
  // 1. Combine smallest 2 notes
  // 2. Repeat until only 2 notes remain
  // Result: 2 notes ready for withdrawal

  const [note1, note2] = await combineToTwoNotes(
    notes,
    "Prepare for withdrawal"
  );

  console.log(`Combined ${notes.length} notes into 2 notes`);
  console.log(`Note 1: ${note1.amount}, Note 2: ${note2.amount}`);

  // Now you can use note1 and note2 for withdrawal
  return [note1, note2];
}

/**
 * USAGE EXAMPLE 3: Smart withdrawal with auto-combining
 *
 * Integrates with note selector
 */
async function smartWithdrawal(allNotes: Note[], withdrawAmount: bigint) {
  const { selectNotesForWithdrawal } = require("./note-selector");

  const result = selectNotesForWithdrawal(allNotes, withdrawAmount);

  if (result.success) {
    // Can withdraw immediately with 1-2 notes
    console.log("✅ Can withdraw immediately");
    return result.notes;
  } else if (result.needsCombining) {
    // Need to combine notes first
    console.log("⚠️  Need to combine notes first");
    console.log(
      `Strategy: ${result.combineStrategy?.steps.length} combining steps`
    );

    // Automatically execute combining strategy
    const twoNotes = await combineToTwoNotes(
      allNotes,
      "Auto-combine for withdrawal"
    );

    // Verify the 2 notes can cover withdrawal
    const total = twoNotes[0].amount + twoNotes[1].amount;
    if (total >= withdrawAmount) {
      console.log("✅ Notes combined, ready to withdraw");
      return twoNotes;
    } else {
      throw new Error("Insufficient balance even after combining");
    }
  } else {
    throw new Error(result.message);
  }
}

/**
 * USAGE EXAMPLE 4: Wallet integration workflow
 */
async function walletWorkflow() {
  // User has many notes in wallet
  const userNotes: Note[] = [
    // ... fetched from wallet storage
  ];

  const withdrawAmount = BigInt(5_000_000_000); // 5 SOL

  console.log(
    `\n📱 Wallet Workflow: Withdraw ${withdrawAmount / BigInt(1e9)} SOL`
  );
  console.log(`   Available notes: ${userNotes.length}`);

  // Step 1: Check if we can withdraw immediately
  const { selectNotesForWithdrawal } = require("./note-selector");
  const selection = selectNotesForWithdrawal(userNotes, withdrawAmount);

  if (selection.success && selection.notes.length <= 2) {
    console.log(`   ✅ Using ${selection.notes.length} existing note(s)`);
    // Proceed with withdrawal using selection.notes
    return selection.notes;
  }

  // Step 2: Need to combine notes
  console.log(`   🔄 Combining ${userNotes.length} notes...`);

  const combinedNotes = await combineToTwoNotes(
    userNotes,
    "Preparing for withdrawal"
  );

  console.log(`   ✅ Combined into 2 notes`);
  console.log(`   📝 Now ready to withdraw`);

  // Step 3: Withdraw using the 2 combined notes
  return combinedNotes;
}

/**
 * ALGORITHM EXPLANATION
 */
console.log(`
═══════════════════════════════════════════════════════════════
HOW THE AUTO-COMBINING WORKS
═══════════════════════════════════════════════════════════════

Function: combineMultipleNotes(notes) - Reduces X notes to 1 note
───────────────────────────────────────────────────────────────
Algorithm:
  1. Start with X notes
  2. While notes.length > 1:
     a. Sort notes by amount (smallest first)
     b. Take the 2 smallest notes
     c. Combine them into 1 note
     d. Add combined note back to pool
  3. Return final single note

Example with 5 notes:
  Start:  [1, 2, 3, 4, 5]
  Step 1: Combine 1+2=3  →  [3, 3, 4, 5]
  Step 2: Combine 3+3=6  →  [4, 5, 6]
  Step 3: Combine 4+5=9  →  [6, 9]
  Step 4: Combine 6+9=15 →  [15]
  Result: 1 note (15)

Function: combineToTwoNotes(notes) - Reduces X notes to 2 notes
───────────────────────────────────────────────────────────────
Algorithm:
  1. Start with X notes
  2. While notes.length > 2:
     a. Sort notes by amount (smallest first)
     b. Take the 2 smallest notes
     c. Combine them into 1 note
     d. Add combined note back to pool
  3. Return final 2 notes

Example with 6 notes:
  Start:  [1, 2, 3, 4, 5, 6]
  Step 1: Combine 1+2=3  →  [3, 3, 4, 5, 6]
  Step 2: Combine 3+3=6  →  [4, 5, 6, 6]
  Step 3: Combine 4+5=9  →  [6, 6, 9]
  Step 4: Combine 6+6=12 →  [9, 12]
  Result: 2 notes ready for withdrawal (9, 12)

Benefits:
  ✅ Fully automatic - just pass in your notes array
  ✅ Handles any number of notes (2 to 1000+)
  ✅ Greedy strategy minimizes intermediate note sizes
  ✅ Ready for withdrawal - outputs exactly 2 notes
  ✅ Transaction count: (n-1) for 1 note, (n-2) for 2 notes

═══════════════════════════════════════════════════════════════
`);

export {
  exampleCombineToOne,
  exampleCombineToTwo,
  smartWithdrawal,
  walletWorkflow,
};
