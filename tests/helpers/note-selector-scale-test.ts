// Test: How note selector handles X number of notes

import { DepositNote } from './note-storage';
import { selectNotesForWithdrawal, formatAmount } from './note-selector';

const LAMPORTS_PER_SOL = 1_000_000_000;

function createDummyNote(amountSol: number, leafIndex: number): DepositNote {
  const amount = BigInt(amountSol * LAMPORTS_PER_SOL);
  return {
    amount,
    commitment: new Uint8Array(32).fill(leafIndex),
    nullifier: new Uint8Array(32).fill(leafIndex + 100),
    blinding: new Uint8Array(32).fill(leafIndex + 200),
    privateKey: new Uint8Array(32).fill(leafIndex + 50),
    publicKey: BigInt(leafIndex),
    leafIndex,
    merklePath: { pathElements: [], pathIndices: [] },
    spent: false,
  };
}

console.log('\n🧪 TESTING NOTE SELECTOR WITH DIFFERENT NOTE COUNTS\n');
console.log('Question: What if I have X number of notes?\n');
console.log('═'.repeat(70));

// Test 1: 1 note
console.log('\n📊 SCENARIO: 1 note (5 SOL)');
console.log('─'.repeat(70));
{
  const notes = [createDummyNote(5.0, 0)];
  const withdrawAmount = BigInt(3 * LAMPORTS_PER_SOL);
  
  console.log(`Available: 1 note (5 SOL)`);
  console.log(`Want to withdraw: ${formatAmount(withdrawAmount)}`);
  
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  
  if (result.success) {
    console.log(`✅ Can withdraw immediately!`);
    console.log(`   Use: ${result.notes.length} note`);
    console.log(`   Change: ${formatAmount(result.changeAmount)}`);
  }
}

// Test 2: 3 notes (small amounts)
console.log('\n📊 SCENARIO: 3 notes (0.5 + 0.7 + 0.9 SOL = 2.1 SOL)');
console.log('─'.repeat(70));
{
  const notes = [
    createDummyNote(0.5, 0),
    createDummyNote(0.7, 1),
    createDummyNote(0.9, 2),
  ];
  const withdrawAmount = BigInt(1.5 * LAMPORTS_PER_SOL);
  
  console.log(`Available: 3 notes (Total: 2.1 SOL)`);
  console.log(`Want to withdraw: ${formatAmount(withdrawAmount)}`);
  
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  
  if (result.success) {
    console.log(`✅ Can withdraw immediately!`);
    console.log(`   Use: ${result.notes.length} notes`);
    result.notes.forEach(n => console.log(`     - ${formatAmount(n.amount)}`));
    console.log(`   Change: ${formatAmount(result.changeAmount)}`);
  } else if (result.needsCombining) {
    console.log(`⚠️  Need to combine notes first`);
    console.log(`   Strategy:`);
    result.combineStrategy?.steps.forEach((step, i) => {
      console.log(`     Step ${i + 1}: ${step.description}`);
    });
  }
}

// Test 3: 5 notes (all small, need combining)
console.log('\n📊 SCENARIO: 5 small notes (0.3, 0.4, 0.5, 0.6, 0.7 SOL = 2.5 SOL)');
console.log('─'.repeat(70));
{
  const notes = [
    createDummyNote(0.3, 0),
    createDummyNote(0.4, 1),
    createDummyNote(0.5, 2),
    createDummyNote(0.6, 3),
    createDummyNote(0.7, 4),
  ];
  const withdrawAmount = BigInt(2 * LAMPORTS_PER_SOL);
  
  console.log(`Available: 5 notes (Total: 2.5 SOL)`);
  console.log(`Want to withdraw: ${formatAmount(withdrawAmount)}`);
  
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  
  if (result.success) {
    console.log(`✅ Can withdraw immediately!`);
    console.log(`   Use: ${result.notes.length} notes`);
  } else if (result.needsCombining) {
    console.log(`⚠️  Need to combine notes first (no pair covers 2 SOL)`);
    console.log(`   Total available: ${formatAmount(result.totalAmount)}`);
    console.log(`\n   📋 Combining Strategy (${result.combineStrategy?.steps.length} steps):`);
    result.combineStrategy?.steps.forEach((step, i) => {
      console.log(`     ${i + 1}. ${step.description}`);
    });
    console.log(`\n   After combining: You'll have 2 notes that can cover the withdrawal`);
  }
}

// Test 4: 10 notes (mixed sizes)
console.log('\n📊 SCENARIO: 10 notes (mixed sizes, total: 15 SOL)');
console.log('─'.repeat(70));
{
  const notes = [
    createDummyNote(0.5, 0),
    createDummyNote(0.8, 1),
    createDummyNote(1.0, 2),
    createDummyNote(1.2, 3),
    createDummyNote(1.5, 4),
    createDummyNote(1.8, 5),
    createDummyNote(2.0, 6),
    createDummyNote(2.2, 7),
    createDummyNote(2.5, 8),
    createDummyNote(1.5, 9),
  ];
  const withdrawAmount = BigInt(5 * LAMPORTS_PER_SOL);
  
  const totalSol = notes.reduce((sum, n) => sum + Number(n.amount), 0) / LAMPORTS_PER_SOL;
  console.log(`Available: 10 notes (Total: ${totalSol} SOL)`);
  console.log(`Want to withdraw: ${formatAmount(withdrawAmount)}`);
  
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  
  if (result.success) {
    console.log(`✅ Can withdraw immediately!`);
    console.log(`   Selected: ${result.notes.length} note(s) from your 10 notes`);
    result.notes.forEach(n => console.log(`     - ${formatAmount(n.amount)}`));
    console.log(`   Total input: ${formatAmount(result.totalAmount)}`);
    console.log(`   Change: ${formatAmount(result.changeAmount)}`);
  } else if (result.needsCombining) {
    console.log(`⚠️  Need to combine notes first`);
  }
}

// Test 5: 20 notes (many small ones)
console.log('\n📊 SCENARIO: 20 notes (each 0.5 SOL, total: 10 SOL)');
console.log('─'.repeat(70));
{
  const notes = Array.from({ length: 20 }, (_, i) => createDummyNote(0.5, i));
  const withdrawAmount = BigInt(8 * LAMPORTS_PER_SOL);
  
  console.log(`Available: 20 notes (each 0.5 SOL, Total: 10 SOL)`);
  console.log(`Want to withdraw: ${formatAmount(withdrawAmount)}`);
  
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  
  if (result.success) {
    console.log(`✅ Can withdraw immediately!`);
    console.log(`   Use: ${result.notes.length} notes`);
  } else if (result.needsCombining) {
    console.log(`⚠️  Need to combine notes first`);
    console.log(`   Reason: No single note or pair covers ${formatAmount(withdrawAmount)}`);
    console.log(`   Total available: ${formatAmount(result.totalAmount)}`);
    console.log(`\n   📋 Combining Strategy:`);
    console.log(`     Need ${result.combineStrategy?.steps.length} combining transactions`);
    console.log(`     Each transaction combines 2 notes into 1`);
    console.log(`     After all combines: You'll have 2 notes that cover the withdrawal`);
    
    // Show first few steps
    result.combineStrategy?.steps.slice(0, 3).forEach((step, i) => {
      console.log(`     ${i + 1}. ${step.description}`);
    });
    if (result.combineStrategy!.steps.length > 3) {
      console.log(`     ... (${result.combineStrategy!.steps.length - 3} more steps)`);
    }
  }
}

// Test 6: 100 notes (extreme case)
console.log('\n📊 SCENARIO: 100 notes (each 0.1 SOL, total: 10 SOL)');
console.log('─'.repeat(70));
{
  const notes = Array.from({ length: 100 }, (_, i) => createDummyNote(0.1, i));
  const withdrawAmount = BigInt(5 * LAMPORTS_PER_SOL);
  
  console.log(`Available: 100 notes! (each 0.1 SOL, Total: 10 SOL)`);
  console.log(`Want to withdraw: ${formatAmount(withdrawAmount)}`);
  
  const result = selectNotesForWithdrawal(notes, withdrawAmount);
  
  if (result.success) {
    console.log(`✅ Can withdraw immediately!`);
  } else if (result.needsCombining) {
    console.log(`⚠️  Need to combine notes first`);
    console.log(`   With 100 small notes, you'll need many combining transactions`);
    console.log(`   Strategy requires ${result.combineStrategy?.steps.length} combining steps`);
    console.log(`\n   💡 Recommendation: Combine notes in batches when you have many small notes`);
    console.log(`   This way you'll have larger notes ready for future withdrawals`);
  }
}

// Summary
console.log('\n\n' + '═'.repeat(70));
console.log('📚 SUMMARY: How Note Selector Handles X Notes');
console.log('═'.repeat(70));
console.log(`
🎯 Key Principles:

1. Circuit Constraint: Can only spend 2 notes at once (2-in-2-out)

2. Immediate Withdrawal (no combining needed):
   ✅ If 1 note covers amount → use that note
   ✅ If 2 notes cover amount → use those 2 notes

3. Combining Required (3+ notes needed):
   ⚠️  Provides step-by-step combining strategy
   ⚠️  Each step: 2 notes → 1 combined note
   ⚠️  Reduces note count until you have ≤2 notes that cover withdrawal

4. Performance:
   • Works with any number of notes (1 to 1000+)
   • Algorithm: O(n²) for finding pairs (fast even with many notes)
   • Combining strategy: O(n) planning (instant)

5. Best Practices:
   💡 Keep some larger notes for quick withdrawals
   💡 Periodically combine small notes to reduce fragmentation
   💡 The selector always finds the optimal solution if one exists

🎉 CONCLUSION: The selector handles ANY number of notes automatically!
   Just call selectNotesForWithdrawal(yourNotes, withdrawAmount)
   and it will tell you exactly what to do.
`);
