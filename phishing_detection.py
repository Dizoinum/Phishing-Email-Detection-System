import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
import re
import warnings
warnings.filterwarnings('ignore')

class PhishingDetectionSystem:
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'Decision Tree': DecisionTreeClassifier(random_state=42),
            'SVM': SVC(kernel='rbf', random_state=42),
            'Naive Bayes': GaussianNB(),
            'KNN': KNeighborsClassifier(n_neighbors=5),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'AdaBoost': AdaBoostClassifier(n_estimators=100, random_state=42),
            'XGBoost': XGBClassifier(n_estimators=100, random_state=42, eval_metric='logloss')
        }
        self.scaler = StandardScaler()
        self.results = {}
        
    def extract_url_features(self, url):
        """Extract features from URL for phishing detection"""
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        
        # URL Length
        features['url_length'] = len(url)
        
        # Domain Length
        features['domain_length'] = len(parsed.netloc)
        
        # Number of dots
        features['num_dots'] = url.count('.')
        
        # Number of hyphens
        features['num_hyphens'] = url.count('-')
        
        # Number of underscores
        features['num_underscores'] = url.count('_')
        
        # Number of slashes
        features['num_slashes'] = url.count('/')
        
        # Number of question marks
        features['num_question'] = url.count('?')
        
        # Number of equal signs
        features['num_equal'] = url.count('=')
        
        # Number of @ symbols
        features['num_at'] = url.count('@')
        
        # Number of ampersands
        features['num_ampersand'] = url.count('&')
        
        # Has IP address
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0
        
        # HTTPS
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        
        # Number of subdomains
        features['num_subdomains'] = len(parsed.netloc.split('.')) - 2 if len(parsed.netloc.split('.')) > 2 else 0
        
        # Has double slash in path
        features['has_double_slash'] = 1 if '//' in parsed.path else 0
        
        # Number of digits in URL
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Number of letters in URL
        features['num_letters'] = sum(c.isalpha() for c in url)
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.info', '.top']
        features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
        
        # Path length
        features['path_length'] = len(parsed.path)
        
        # Query length
        features['query_length'] = len(parsed.query)
        
        # Has port
        features['has_port'] = 1 if parsed.port else 0
        
        return features
    
    def generate_synthetic_data(self, n_samples=5000):
        """Generate synthetic phishing dataset"""
        print("Generating synthetic phishing dataset...")
        
        # Legitimate URLs patterns
        legit_urls = []
        legit_domains = ['google.com', 'amazon.com', 'facebook.com', 'microsoft.com', 
                        'apple.com', 'github.com', 'wikipedia.org', 'youtube.com',
                        'linkedin.com', 'twitter.com', 'instagram.com', 'reddit.com']
        
        for _ in range(n_samples // 2):
            domain = np.random.choice(legit_domains)
            path = '/' + '/'.join(np.random.choice(['about', 'contact', 'products', 'services', ''], 
                                                   size=np.random.randint(0, 3)))
            url = f"https://{domain}{path}"
            legit_urls.append(url)
        
        # Phishing URLs patterns
        phish_urls = []
        for _ in range(n_samples // 2):
            # Create suspicious patterns
            domain_base = np.random.choice(legit_domains).replace('.', '')
            suspicious_patterns = [
                f"http://{domain_base}-verify.tk/login.php?user=",
                f"https://{domain_base}{np.random.randint(100, 999)}.xyz/secure/",
                f"http://secure-{domain_base}.ml/account/verify/",
                f"https://{domain_base}.verification-center.info/",
                f"http://{domain_base}-update.cf/signin.php?redirect=",
            ]
            url = np.random.choice(suspicious_patterns) + ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 
                                                                                    size=np.random.randint(5, 15)))
            phish_urls.append(url)
        
        # Extract features
        all_urls = legit_urls + phish_urls
        labels = [0] * len(legit_urls) + [1] * len(phish_urls)
        
        features_list = []
        for url in all_urls:
            features_list.append(self.extract_url_features(url))
        
        # Create DataFrame
        df = pd.DataFrame(features_list)
        df['label'] = labels
        
        print(f"Dataset created: {len(df)} samples")
        print(f"Legitimate URLs: {sum(df['label'] == 0)}")
        print(f"Phishing URLs: {sum(df['label'] == 1)}")
        
        return df
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train all models and collect metrics"""
        print("\n" + "="*70)
        print("TRAINING MULTIPLE MODELS FOR PHISHING DETECTION")
        print("="*70 + "\n")
        
        for name, model in self.models.items():
            print(f"Training {name}...")
            
            # Train model
            model.fit(X_train, y_train)
            
            # Predictions
            y_pred = model.predict(X_test)
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            # Cross-validation score
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            cv_mean = cv_scores.mean()
            
            # Store results
            self.results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'cv_score': cv_mean,
                'confusion_matrix': confusion_matrix(y_test, y_pred)
            }
            
            print(f"  Accuracy: {accuracy:.4f} | Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")
        
        print("\n" + "="*70 + "\n")
    
    def plot_results(self):
        """Create comprehensive graphical report with individual displays"""
        # Extract metrics
        model_names = list(self.results.keys())
        accuracies = [self.results[m]['accuracy'] for m in model_names]
        precisions = [self.results[m]['precision'] for m in model_names]
        recalls = [self.results[m]['recall'] for m in model_names]
        f1_scores = [self.results[m]['f1_score'] for m in model_names]
        cv_scores = [self.results[m]['cv_score'] for m in model_names]
        
        print("\n" + "="*70)
        print("DISPLAYING VISUALIZATIONS (Press any key to continue)")
        print("="*70 + "\n")
        
        # 1. Accuracy Comparison Bar Chart
        print("📊 Chart 1/9: Model Accuracy Comparison")
        fig1 = plt.figure(figsize=(12, 7))
        bars = plt.bar(range(len(model_names)), accuracies, color='steelblue', alpha=0.8, edgecolor='black')
        plt.xlabel('Models', fontsize=14, fontweight='bold')
        plt.ylabel('Accuracy', fontsize=14, fontweight='bold')
        plt.title('Model Accuracy Comparison', fontsize=16, fontweight='bold', pad=20)
        plt.xticks(range(len(model_names)), model_names, rotation=45, ha='right', fontsize=11)
        plt.ylim([0, 1.1])
        plt.grid(axis='y', alpha=0.3, linestyle='--')
        
        # Add value labels on bars
        for i, bar in enumerate(bars):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{accuracies[i]:.4f}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('chart_1_accuracy_comparison.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 2. All Metrics Comparison
        print("\n📊 Chart 2/9: All Metrics Comparison")
        fig2 = plt.figure(figsize=(14, 7))
        x = np.arange(len(model_names))
        width = 0.2
        
        plt.bar(x - 1.5*width, accuracies, width, label='Accuracy', alpha=0.8, color='#1f77b4')
        plt.bar(x - 0.5*width, precisions, width, label='Precision', alpha=0.8, color='#ff7f0e')
        plt.bar(x + 0.5*width, recalls, width, label='Recall', alpha=0.8, color='#2ca02c')
        plt.bar(x + 1.5*width, f1_scores, width, label='F1-Score', alpha=0.8, color='#d62728')
        
        plt.xlabel('Models', fontsize=14, fontweight='bold')
        plt.ylabel('Score', fontsize=14, fontweight='bold')
        plt.title('All Metrics Comparison', fontsize=16, fontweight='bold', pad=20)
        plt.xticks(x, model_names, rotation=45, ha='right', fontsize=11)
        plt.legend(fontsize=12, loc='lower right')
        plt.ylim([0, 1.1])
        plt.grid(axis='y', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig('chart_2_all_metrics.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 3. Precision vs Recall
        print("\n📊 Chart 3/9: Precision vs Recall Trade-off")
        fig3 = plt.figure(figsize=(12, 8))
        scatter = plt.scatter(recalls, precisions, s=300, c=accuracies, cmap='viridis', 
                             alpha=0.7, edgecolors='black', linewidth=2)
        for i, name in enumerate(model_names):
            plt.annotate(name, (recalls[i], precisions[i]), fontsize=10, ha='center', 
                        fontweight='bold', color='white',
                        bbox=dict(boxstyle='round,pad=0.3', facecolor='black', alpha=0.7))
        plt.xlabel('Recall', fontsize=14, fontweight='bold')
        plt.ylabel('Precision', fontsize=14, fontweight='bold')
        plt.title('Precision vs Recall (colored by Accuracy)', fontsize=16, fontweight='bold', pad=20)
        cbar = plt.colorbar(scatter, label='Accuracy')
        cbar.set_label('Accuracy', fontsize=12, fontweight='bold')
        plt.grid(alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig('chart_3_precision_recall.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 4. F1-Score Comparison
        print("\n📊 Chart 4/9: F1-Score Comparison")
        fig4 = plt.figure(figsize=(12, 8))
        colors = plt.cm.viridis(np.linspace(0, 1, len(model_names)))
        bars = plt.barh(range(len(model_names)), f1_scores, color=colors, alpha=0.8, edgecolor='black')
        plt.yticks(range(len(model_names)), model_names, fontsize=12)
        plt.xlabel('F1-Score', fontsize=14, fontweight='bold')
        plt.title('F1-Score Comparison', fontsize=16, fontweight='bold', pad=20)
        plt.xlim([0, 1.1])
        plt.grid(axis='x', alpha=0.3, linestyle='--')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            plt.text(width + 0.01, bar.get_y() + bar.get_height()/2.,
                    f'{f1_scores[i]:.4f}',
                    ha='left', va='center', fontsize=11, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('chart_4_f1_score.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 5. Cross-Validation Scores
        print("\n📊 Chart 5/9: Cross-Validation Scores (5-Fold)")
        fig5 = plt.figure(figsize=(12, 7))
        bars = plt.bar(range(len(model_names)), cv_scores, color='coral', alpha=0.8, edgecolor='black')
        plt.xlabel('Models', fontsize=14, fontweight='bold')
        plt.ylabel('CV Score', fontsize=14, fontweight='bold')
        plt.title('Cross-Validation Scores (5-Fold)', fontsize=16, fontweight='bold', pad=20)
        plt.xticks(range(len(model_names)), model_names, rotation=45, ha='right', fontsize=11)
        plt.ylim([0, 1.1])
        plt.grid(axis='y', alpha=0.3, linestyle='--')
        
        for i, bar in enumerate(bars):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{cv_scores[i]:.4f}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('chart_5_cv_scores.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 6. Radar Chart for Top 3 Models
        print("\n📊 Chart 6/9: Top 3 Models - Metrics Radar")
        fig6 = plt.figure(figsize=(10, 10))
        
        # Get top 3 models by accuracy
        top_3_indices = np.argsort(accuracies)[-3:]
        categories = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        N = len(categories)
        angles = [n / float(N) * 2 * np.pi for n in range(N)]
        angles += angles[:1]
        
        ax = plt.subplot(111, projection='polar')
        
        colors_radar = ['#1f77b4', '#ff7f0e', '#2ca02c']
        for idx, color in zip(top_3_indices, colors_radar):
            values = [accuracies[idx], precisions[idx], recalls[idx], f1_scores[idx]]
            values += values[:1]
            ax.plot(angles, values, 'o-', linewidth=3, label=model_names[idx], color=color)
            ax.fill(angles, values, alpha=0.25, color=color)
        
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=13, fontweight='bold')
        ax.set_ylim(0, 1)
        ax.set_title('Top 3 Models - Metrics Radar', fontsize=16, fontweight='bold', pad=30)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=12)
        ax.grid(True, linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        plt.savefig('chart_6_radar.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 7. Confusion Matrix for Best Model
        best_model_name = model_names[np.argmax(accuracies)]
        cm = self.results[best_model_name]['confusion_matrix']
        
        print(f"\n📊 Chart 7/9: Confusion Matrix - {best_model_name}")
        fig7 = plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True, 
                   xticklabels=['Legitimate', 'Phishing'],
                   yticklabels=['Legitimate', 'Phishing'],
                   annot_kws={'size': 16, 'weight': 'bold'},
                   cbar_kws={'label': 'Count'},
                   linewidths=2, linecolor='black')
        plt.title(f'Confusion Matrix - {best_model_name}', fontsize=16, fontweight='bold', pad=20)
        plt.ylabel('True Label', fontsize=14, fontweight='bold')
        plt.xlabel('Predicted Label', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig('chart_7_confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 8. Model Ranking
        print("\n📊 Chart 8/9: Model Ranking by Accuracy")
        fig8 = plt.figure(figsize=(12, 8))
        sorted_indices = np.argsort(accuracies)
        sorted_names = [model_names[i] for i in sorted_indices]
        sorted_accuracies = [accuracies[i] for i in sorted_indices]
        
        colors_gradient = plt.cm.RdYlGn(np.linspace(0.3, 0.9, len(sorted_names)))
        bars = plt.barh(range(len(sorted_names)), sorted_accuracies, color=colors_gradient, 
                       alpha=0.8, edgecolor='black')
        plt.yticks(range(len(sorted_names)), sorted_names, fontsize=12)
        plt.xlabel('Accuracy', fontsize=14, fontweight='bold')
        plt.title('Model Ranking by Accuracy', fontsize=16, fontweight='bold', pad=20)
        plt.xlim([0, 1.1])
        plt.grid(axis='x', alpha=0.3, linestyle='--')
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            plt.text(width + 0.01, bar.get_y() + bar.get_height()/2.,
                    f'{sorted_accuracies[i]:.4f}',
                    ha='left', va='center', fontsize=11, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('chart_8_model_ranking.png', dpi=300, bbox_inches='tight')
        plt.show()
        input("Press Enter to continue...")
        
        # 9. Summary Statistics Table
        print("\n📊 Chart 9/9: Summary Report")
        fig9 = plt.figure(figsize=(14, 10))
        plt.axis('off')
        
        summary_text = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║         PHISHING DETECTION SYSTEM - COMPREHENSIVE SUMMARY             ║
╚═══════════════════════════════════════════════════════════════════════╝

OVERALL STATISTICS
{'─'*75}
Total Models Evaluated: {len(model_names)}
Dataset Size: 5000 samples (2500 legitimate, 2500 phishing)

BEST PERFORMING MODEL
{'─'*75}
🏆 Model Name:       {best_model_name}
   Accuracy:         {max(accuracies):.4f}
   Precision:        {precisions[np.argmax(accuracies)]:.4f}
   Recall:           {recalls[np.argmax(accuracies)]:.4f}
   F1-Score:         {max(f1_scores):.4f}
   CV Score:         {cv_scores[np.argmax(accuracies)]:.4f}

AVERAGE PERFORMANCE ACROSS ALL MODELS
{'─'*75}
   Average Accuracy:    {np.mean(accuracies):.4f}
   Average Precision:   {np.mean(precisions):.4f}
   Average Recall:      {np.mean(recalls):.4f}
   Average F1-Score:    {np.mean(f1_scores):.4f}
   Average CV Score:    {np.mean(cv_scores):.4f}

PERFORMANCE RANGE
{'─'*75}
   Accuracy Range:      {min(accuracies):.4f} - {max(accuracies):.4f}
   F1-Score Range:      {min(f1_scores):.4f} - {max(f1_scores):.4f}

HIGHEST CROSS-VALIDATION SCORE
{'─'*75}
   Model: {model_names[np.argmax(cv_scores)]}
   CV Score: {max(cv_scores):.4f}

TOP 3 MODELS BY ACCURACY
{'─'*75}"""
        
        # Add top 3 models
        for rank, idx in enumerate(np.argsort(accuracies)[-3:][::-1], 1):
            summary_text += f"\n   {rank}. {model_names[idx]:<25} Accuracy: {accuracies[idx]:.4f}"
        
        summary_text += f"""

CONFUSION MATRIX ANALYSIS (Best Model: {best_model_name})
{'─'*75}
   True Negatives:  {cm[0][0]}
   False Positives: {cm[0][1]}
   False Negatives: {cm[1][0]}
   True Positives:  {cm[1][1]}

GENERATED OUTPUTS
{'─'*75}
   ✓ 8 Individual chart images saved
   ✓ This summary report displayed
   ✓ All metrics calculated and compared

╔═══════════════════════════════════════════════════════════════════════╗
║                    ANALYSIS COMPLETE - {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}                 ║
╚═══════════════════════════════════════════════════════════════════════╝
        """
        
        plt.text(0.5, 0.5, summary_text, fontsize=11, verticalalignment='center',
                horizontalalignment='center', fontfamily='monospace', 
                bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8, pad=1))
        
        plt.tight_layout()
        plt.savefig('chart_9_summary_report.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("\n" + "="*70)
        print("✅ ALL VISUALIZATIONS DISPLAYED SUCCESSFULLY!")
        print("="*70)
        print("\n📁 Saved Files:")
        print("   • chart_1_accuracy_comparison.png")
        print("   • chart_2_all_metrics.png")
        print("   • chart_3_precision_recall.png")
        print("   • chart_4_f1_score.png")
        print("   • chart_5_cv_scores.png")
        print("   • chart_6_radar.png")
        print("   • chart_7_confusion_matrix.png")
        print("   • chart_8_model_ranking.png")
        print("   • chart_9_summary_report.png")
        print("\n" + "="*70 + "\n")
    
    def print_detailed_report(self):
        """Print detailed text report"""
        print("\n" + "="*70)
        print("DETAILED PERFORMANCE REPORT")
        print("="*70 + "\n")
        
        for name, metrics in self.results.items():
            print(f"\n{name}:")
            print(f"  Accuracy:   {metrics['accuracy']:.4f}")
            print(f"  Precision:  {metrics['precision']:.4f}")
            print(f"  Recall:     {metrics['recall']:.4f}")
            print(f"  F1-Score:   {metrics['f1_score']:.4f}")
            print(f"  CV Score:   {metrics['cv_score']:.4f}")
        
        print("\n" + "="*70)
        
        # Best model
        best_model = max(self.results.items(), key=lambda x: x[1]['accuracy'])
        print(f"\n🏆 BEST MODEL: {best_model[0]}")
        print(f"   Accuracy: {best_model[1]['accuracy']:.4f}")
        print("\n" + "="*70 + "\n")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     PHISHING DETECTION SYSTEM - MULTI-MODEL ANALYSIS         ║
    ║                                                              ║
    ║  This system trains and evaluates 9 machine learning        ║
    ║  models for phishing URL detection and generates a          ║
    ║  comprehensive graphical performance report.                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize system
    system = PhishingDetectionSystem()
    
    # Generate synthetic dataset
    df = system.generate_synthetic_data(n_samples=5000)
    
    # Prepare data
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale features
    X_train_scaled = system.scaler.fit_transform(X_train)
    X_test_scaled = system.scaler.transform(X_test)
    
    # Train all models
    system.train_models(X_train_scaled, X_test_scaled, y_train, y_test)
    
    # Print detailed report
    system.print_detailed_report()
    
    # Generate graphical report
    print("\nGenerating comprehensive graphical report...")
    system.plot_results()
    
    print("\n✅ Phishing Detection System Analysis Complete!")
    print("📊 Check 'phishing_detection_report.png' for visual analysis")

if __name__ == "__main__":
    main()
