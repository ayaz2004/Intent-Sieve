"""
Test Matrix - CSV Dataset Evaluation
=====================================
Comprehensive testing of Intense Sieve security system using the CSV dataset.
Generates performance metrics, confusion matrix, and category-based analysis.

Usage: python test_matrix.py
"""

import csv
import sys
import os
from collections import defaultdict
import json

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.isolation import ContextualIsolator
from src.detectors import InjectionDetector

# Configuration
RISK_THRESHOLD = 0.5  # Risk score above this = detected as attack


def load_dataset(filepath='test_dataset.csv'):
    """Load test dataset from CSV file."""
    dataset = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dataset.append({
                    'id': row['id'],
                    'text': row['text'],
                    'tool_name': row.get('tool_name', ''),
                    'tool_args': row.get('tool_args', ''),
                    'is_attack': row['is_attack'].upper() == 'TRUE',
                    'category': row['category'],
                    'source': row.get('source', 'unknown')
                })
        print(f"[OK] Loaded {len(dataset)} test cases from {filepath}")
        return dataset
    except FileNotFoundError:
        print(f"[ERROR] {filepath} not found")
        return []
    except Exception as e:
        print(f"[ERROR] loading dataset: {e}")
        return []


def test_security_layers(text, tool_name='', tool_args=''):
    """
    Run text through all security layers and return detection result.
    
    Args:
        text: User input text
        tool_name: Name of the tool being called
        tool_args: Arguments for the tool
    
    Returns:
        dict: {
            'detected': bool,
            'risk_score': float,
            'threats': list,
            'isolation_meta': dict
        }
    """
    # Layer 0: Isolation (includes leetspeak normalization)
    isolator = ContextualIsolator()
    cleaned, isolation_meta = isolator.sanitize(text)
    
    # Layer 0.5: Detection
    detector = InjectionDetector()
    threats, risk_score = detector.analyze(cleaned)
    
    # Layer 1: Intent-Action Validation (for semantic drift)
    intent_mismatch = check_intent_action_mismatch(text, tool_name, tool_args)
    if intent_mismatch:
        risk_score = max(risk_score, 0.85)  # High risk for mismatched intent
    
    # Determine if attack was detected
    detected = risk_score >= RISK_THRESHOLD
    
    return {
        'detected': detected,
        'risk_score': risk_score,
        'threats': len(threats),
        'isolation_meta': isolation_meta
    }


def check_intent_action_mismatch(text, tool_name, tool_args):
    """
    Check if the user's stated intent matches the proposed action.
    
    This catches semantic drift attacks where benign text triggers dangerous actions.
    Example: "Show documentation" → delete_system_files()
    
    Returns:
        bool: True if there's a mismatch (potential attack)
    """
    if not tool_name:
        return False
    
    text_lower = text.lower()
    tool_lower = tool_name.lower()
    
    # Safe action verbs (reading/viewing)
    safe_verbs = ['show', 'read', 'view', 'display', 'open', 'get', 'fetch', 
                  'load', 'see', 'look', 'check', 'list', 'help']
    
    # Destructive action verbs
    destructive_verbs = ['delete', 'remove', 'erase', 'clear', 'purge', 'wipe', 
                         'destroy', 'drop']
    
    # Check for semantic drift: safe verb in text but destructive tool
    has_safe_verb = any(verb in text_lower for verb in safe_verbs)
    has_destructive_verb = any(verb in text_lower for verb in destructive_verbs)
    is_destructive_tool = 'delete' in tool_lower or 'remove' in tool_lower
    
    # Mismatch: User asks to "show/read" but tool will "delete"
    if has_safe_verb and not has_destructive_verb and is_destructive_tool:
        return True
    
    # Check for generic requests that shouldn't trigger destructive actions
    generic_requests = ['documentation', 'code', 'file', 'notes', 'manual', 
                       'instructions', 'setup', 'config']
    is_generic = any(req in text_lower for req in generic_requests)
    
    if is_generic and not has_destructive_verb and is_destructive_tool:
        return True
    
    return False


def calculate_metrics(results):
    """Calculate performance metrics from test results."""
    tp = sum(1 for r in results if r['actual_attack'] and r['detected'])
    tn = sum(1 for r in results if not r['actual_attack'] and not r['detected'])
    fp = sum(1 for r in results if not r['actual_attack'] and r['detected'])
    fn = sum(1 for r in results if r['actual_attack'] and not r['detected'])
    
    total = len(results)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'tp': tp,
        'tn': tn,
        'fp': fp,
        'fn': fn,
        'total': total,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }


def analyze_by_category(results):
    """Analyze results grouped by attack category."""
    category_stats = defaultdict(lambda: {'total': 0, 'detected': 0, 'missed': 0})
    
    for r in results:
        cat = r['category']
        category_stats[cat]['total'] += 1
        
        if r['actual_attack']:
            if r['detected']:
                category_stats[cat]['detected'] += 1
            else:
                category_stats[cat]['missed'] += 1
    
    return dict(category_stats)


def print_simple_table(metrics, category_stats):
    """Print a simple comprehensive results table."""
    print("\n" + "="*90)
    print("SIMPLE RESULTS TABLE")
    print("="*90)
    
    # Overall Performance Table
    print("\n[OVERALL PERFORMANCE]")
    print(f"{'Metric':<20} {'Value':<15} {'Details'}")
    print("-" * 90)
    print(f"{'Total Cases':<20} {metrics['total']:<15} {metrics['tp']} TP, {metrics['tn']} TN, {metrics['fp']} FP, {metrics['fn']} FN")
    print(f"{'Accuracy':<20} {metrics['accuracy']:.2%}           {metrics['tp']+metrics['tn']}/{metrics['total']} correct predictions")
    print(f"{'Precision':<20} {metrics['precision']:.2%}           {metrics['tp']}/{metrics['tp']+metrics['fp']} of flagged were actual attacks")
    print(f"{'Recall':<20} {metrics['recall']:.2%}           {metrics['tp']}/{metrics['tp']+metrics['fn']} of attacks were caught")
    print(f"{'F1 Score':<20} {metrics['f1']:.2%}           Harmonic mean of precision and recall")
    
    # Category Performance Table
    print("\n[CATEGORY PERFORMANCE]")
    print(f"{'Category':<25} {'Total':<8} {'Detected':<10} {'Missed':<8} {'Rate':<10} {'Status'}")
    print("-" * 90)
    
    # Sort categories by detection rate
    sorted_cats = []
    for cat in category_stats.keys():
        if cat == 'benign':
            continue
        stats = category_stats[cat]
        total = stats['total']
        detected = stats['detected']
        missed = stats['missed']
        rate = detected / total if total > 0 else 0
        sorted_cats.append((cat, total, detected, missed, rate))
    
    sorted_cats.sort(key=lambda x: x[4], reverse=True)  # Sort by rate
    
    for cat, total, detected, missed, rate in sorted_cats:
        status = "[OK]" if rate >= 0.9 else "[!!]" if rate >= 0.7 else "[XX]"
        print(f"{cat:<25} {total:<8} {detected:<10} {missed:<8} {rate:<9.1%} {status}")
    
    # Benign (safe) cases
    benign = category_stats.get('benign', {'total': 0, 'detected': 0, 'missed': 0})
    if benign['total'] > 0:
        false_positives = metrics['fp']
        true_negatives = metrics['tn']
        benign_rate = true_negatives / benign['total'] if benign['total'] > 0 else 0
        status = "[OK]" if benign_rate >= 0.9 else "[!!]"
        print(f"{'benign (safe queries)':<25} {benign['total']:<8} {false_positives} FP    {true_negatives} TN{' ':<6} {benign_rate:<9.1%} {status}")
    
    print("="*90)


def print_results(metrics, category_stats, results):
    """Print comprehensive test results."""
    print("\n" + "="*70)
    print("TEST MATRIX RESULTS")
    print("="*70)
    
    # Overall Metrics
    print(f"\n[OVERALL PERFORMANCE]")
    print(f"   Total Test Cases: {metrics['total']}")
    print(f"   Accuracy:  {metrics['accuracy']:.2%}")
    print(f"   Precision: {metrics['precision']:.2%}")
    print(f"   Recall:    {metrics['recall']:.2%}")
    print(f"   F1 Score:  {metrics['f1']:.2%}")
    
    # Confusion Matrix
    print(f"\n[CONFUSION MATRIX]")
    print(f"                    Predicted")
    print(f"                 Attack    Safe")
    print(f"   Actual Attack   {metrics['tp']:4d}    {metrics['fn']:4d}   (True Pos / False Neg)")
    print(f"   Actual Safe     {metrics['fp']:4d}    {metrics['tn']:4d}   (False Pos / True Neg)")
    
    # Category Breakdown
    print(f"\n[CATEGORY BREAKDOWN]")
    print(f"   {'Category':<25} {'Total':>7} {'Detected':>10} {'Missed':>8} {'Rate':>8}")
    print(f"   {'-'*25} {'-'*7} {'-'*10} {'-'*8} {'-'*8}")
    
    for cat in sorted(category_stats.keys()):
        stats = category_stats[cat]
        total = stats['total']
        detected = stats['detected']
        missed = stats['missed']
        rate = detected / total if total > 0 else 0
        
        # Only show detection rate for attack categories
        if detected + missed > 0:
            print(f"   {cat:<25} {total:>7} {detected:>10} {missed:>8} {rate:>7.1%}")
        else:
            print(f"   {cat:<25} {total:>7}      -          -         -")
    
    # Risk Score Distribution
    attack_risks = [r['risk_score'] for r in results if r['actual_attack']]
    safe_risks = [r['risk_score'] for r in results if not r['actual_attack']]
    
    print(f"\n[RISK SCORE DISTRIBUTION]")
    if attack_risks:
        print(f"   Attack samples: Min={min(attack_risks):.3f}, Max={max(attack_risks):.3f}, "
              f"Avg={sum(attack_risks)/len(attack_risks):.3f}")
    if safe_risks:
        print(f"   Safe samples:   Min={min(safe_risks):.3f}, Max={max(safe_risks):.3f}, "
              f"Avg={sum(safe_risks)/len(safe_risks):.3f}")
    
    # Sample Failures
    print(f"\n[FALSE NEGATIVES - Missed Attacks] Sample:")
    fn_samples = [r for r in results if r['actual_attack'] and not r['detected']][:5]
    for r in fn_samples:
        text_preview = r['text'][:60] + "..." if len(r['text']) > 60 else r['text']
        print(f"   [{r['category']}] Risk={r['risk_score']:.3f}: {text_preview}")
    
    print(f"\n[FALSE POSITIVES - Incorrectly Flagged] Sample:")
    fp_samples = [r for r in results if not r['actual_attack'] and r['detected']][:5]
    for r in fp_samples:
        text_preview = r['text'][:60] + "..." if len(r['text']) > 60 else r['text']
        print(f"   [{r['category']}] Risk={r['risk_score']:.3f}: {text_preview}")
    
    print("\n" + "="*70)
    
    # Add simple table at the end
    print_simple_table(metrics, category_stats)


def main():
    """Main test execution."""
    print("\n[INTENSE SIEVE - TEST MATRIX EVALUATION]")
    print("="*70)
    print(f"Risk Threshold: {RISK_THRESHOLD}")
    print("="*70)
    
    # Load dataset
    dataset = load_dataset()
    if not dataset:
        print("ERROR: No dataset loaded. Exiting.")
        return
    
    # Run tests
    print(f"\nTesting {len(dataset)} cases...")
    results = []
    
    for i, test_case in enumerate(dataset, 1):
        if i % 50 == 0:
            print(f"   Progress: {i}/{len(dataset)}...")
        
        test_result = test_security_layers(
            test_case['text'],
            test_case.get('tool_name', ''),
            test_case.get('tool_args', '')
        )
        
        results.append({
            'id': test_case['id'],
            'text': test_case['text'],
            'category': test_case['category'],
            'actual_attack': test_case['is_attack'],
            'detected': test_result['detected'],
            'risk_score': test_result['risk_score'],
            'threats': test_result['threats']
        })
    
    print(f"[DONE] Completed testing {len(results)} cases\n")
    
    # Calculate metrics
    metrics = calculate_metrics(results)
    category_stats = analyze_by_category(results)
    
    # Print results
    print_results(metrics, category_stats, results)
    
    # Save detailed results
    output_file = 'test_matrix_results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'metrics': metrics,
            'category_stats': category_stats,
            'threshold': RISK_THRESHOLD,
            'total_tests': len(results)
        }, f, indent=2)
    
    # Save simple table to text file
    table_file = 'test_results_table.txt'
    import sys
    original_stdout = sys.stdout
    with open(table_file, 'w', encoding='utf-8') as f:
        sys.stdout = f
        print_simple_table(metrics, category_stats)
    sys.stdout = original_stdout
    
    print(f"\n[SAVED] Detailed results: {output_file}")
    print(f"[SAVED] Simple table: {table_file}")


if __name__ == "__main__":
    main()
