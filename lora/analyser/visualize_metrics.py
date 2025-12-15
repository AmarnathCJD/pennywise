"""
Training Metrics Visualization Script
Generates graphs and visualizations from training logs and metrics
"""

import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
import numpy as np

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
colors = ['#2ecc71', '#3498db', '#e74c3c', '#f39c12', '#9b59b6']

def load_metrics():
    """Load training metrics from JSON file"""
    metrics_path = Path("./lora-out/training_metrics.json")
    if not metrics_path.exists():
        print("❌ training_metrics.json not found!")
        return None
    
    with open(metrics_path, 'r') as f:
        return json.load(f)

def parse_trainer_state():
    """Parse trainer_state.json for detailed training history"""
    state_path = Path("./lora-out/checkpoint-120/trainer_state.json")
    if state_path.exists():
        with open(state_path, 'r') as f:
            return json.load(f)
    return None

def create_loss_graph(metrics, trainer_state):
    """Create training and evaluation loss graph"""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    if trainer_state and 'log_history' in trainer_state:
        log_history = trainer_state['log_history']
        
        # Extract training loss
        train_steps = []
        train_losses = []
        eval_steps = []
        eval_losses = []
        
        for entry in log_history:
            if 'loss' in entry:
                train_steps.append(entry['step'])
                train_losses.append(entry['loss'])
            if 'eval_loss' in entry:
                eval_steps.append(entry['step'])
                eval_losses.append(entry['eval_loss'])
        
        # Plot training loss
        if train_steps:
            ax.plot(train_steps, train_losses, 'o-', color=colors[0], 
                   linewidth=2, markersize=6, label='Training Loss', alpha=0.8)
        
        # Plot evaluation loss
        if eval_steps:
            ax.plot(eval_steps, eval_losses, 's-', color=colors[1], 
                   linewidth=2, markersize=8, label='Evaluation Loss', alpha=0.8)
    else:
        # Fallback to summary metrics
        final_loss = metrics['training_results']['final_loss']
        eval_loss = metrics['evaluation_results']['eval_loss']
        
        ax.bar(['Training Loss', 'Evaluation Loss'], [final_loss, eval_loss],
               color=[colors[0], colors[1]], alpha=0.7, edgecolor='black', linewidth=1.5)
    
    ax.set_xlabel('Training Step', fontsize=12, fontweight='bold')
    ax.set_ylabel('Loss', fontsize=12, fontweight='bold')
    ax.set_title('Training & Evaluation Loss Over Time', fontsize=14, fontweight='bold', pad=20)
    ax.legend(fontsize=10, loc='upper right', framealpha=0.9)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('./lora-out/loss_graph.png', dpi=300, bbox_inches='tight')
    print("✅ Saved: loss_graph.png")
    plt.close()

def create_metrics_summary(metrics):
    """Create a comprehensive metrics summary visualization"""
    fig = plt.figure(figsize=(14, 10))
    
    # Create grid layout
    gs = fig.add_gridspec(3, 2, hspace=0.4, wspace=0.3)
    
    # 1. Loss Comparison Bar Chart
    ax1 = fig.add_subplot(gs[0, 0])
    train_loss = metrics['training_results']['final_loss']
    eval_loss = metrics['evaluation_results']['eval_loss']
    
    bars = ax1.bar(['Training', 'Evaluation'], [train_loss, eval_loss],
                   color=[colors[0], colors[1]], alpha=0.7, edgecolor='black', linewidth=2)
    ax1.set_ylabel('Loss', fontweight='bold')
    ax1.set_title('Final Loss Comparison', fontweight='bold', fontsize=12)
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.4f}', ha='center', va='bottom', fontweight='bold')
    
    # 2. Dataset Distribution Pie Chart
    ax2 = fig.add_subplot(gs[0, 1])
    train_samples = metrics['dataset_info']['training_samples']
    eval_samples = metrics['dataset_info']['evaluation_samples']
    
    wedges, texts, autotexts = ax2.pie([train_samples, eval_samples], 
                                        labels=['Training', 'Evaluation'],
                                        autopct='%1.1f%%',
                                        colors=[colors[0], colors[1]],
                                        startangle=90,
                                        explode=(0.05, 0.05))
    ax2.set_title('Dataset Split', fontweight='bold', fontsize=12)
    
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    
    # 3. Training Configuration Table
    ax3 = fig.add_subplot(gs[1, :])
    ax3.axis('off')
    
    config = metrics['training_config']
    config_data = [
        ['Batch Size', str(config['batch_size'])],
        ['Gradient Accumulation', str(config['gradient_accumulation_steps'])],
        ['Learning Rate', f"{config['learning_rate']:.0e}"],
        ['Max Length', str(config['max_length'])],
        ['Epochs', str(config['epochs'])],
    ]
    
    table = ax3.table(cellText=config_data,
                     colLabels=['Parameter', 'Value'],
                     cellLoc='left',
                     loc='center',
                     colWidths=[0.6, 0.4])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)
    
    # Style the table
    for i in range(len(config_data) + 1):
        for j in range(2):
            cell = table[(i, j)]
            if i == 0:
                cell.set_facecolor('#3498db')
                cell.set_text_props(weight='bold', color='white')
            else:
                cell.set_facecolor('#ecf0f1' if i % 2 == 0 else 'white')
    
    ax3.set_title('Training Configuration', fontweight='bold', fontsize=12, pad=20)
    
    # 4. Performance Metrics
    ax4 = fig.add_subplot(gs[2, 0])
    ax4.axis('off')
    
    eval_results = metrics['evaluation_results']
    perf_data = [
        ['Eval Loss', f"{eval_results['eval_loss']:.4f}"],
        ['Eval Runtime', f"{eval_results['eval_runtime']:.2f}s"],
        ['Samples/Second', f"{eval_results['eval_samples_per_second']:.2f}"],
    ]
    
    perf_table = ax4.table(cellText=perf_data,
                          colLabels=['Metric', 'Value'],
                          cellLoc='left',
                          loc='center',
                          colWidths=[0.6, 0.4])
    perf_table.auto_set_font_size(False)
    perf_table.set_fontsize(10)
    perf_table.scale(1, 2)
    
    for i in range(len(perf_data) + 1):
        for j in range(2):
            cell = perf_table[(i, j)]
            if i == 0:
                cell.set_facecolor('#2ecc71')
                cell.set_text_props(weight='bold', color='white')
            else:
                cell.set_facecolor('#ecf0f1' if i % 2 == 0 else 'white')
    
    ax4.set_title('Evaluation Performance', fontweight='bold', fontsize=12, pad=20)
    
    # 5. Model Information
    ax5 = fig.add_subplot(gs[2, 1])
    ax5.axis('off')
    
    model_info = [
        ['Model', metrics['model'].split('/')[-1]],
        ['Total Samples', str(metrics['dataset_info']['total_samples'])],
        ['Training Samples', str(metrics['dataset_info']['training_samples'])],
        ['Eval Samples', str(metrics['dataset_info']['evaluation_samples'])],
    ]
    
    model_table = ax5.table(cellText=model_info,
                           colLabels=['Property', 'Value'],
                           cellLoc='left',
                           loc='center',
                           colWidths=[0.6, 0.4])
    model_table.auto_set_font_size(False)
    model_table.set_fontsize(10)
    model_table.scale(1, 2)
    
    for i in range(len(model_info) + 1):
        for j in range(2):
            cell = model_table[(i, j)]
            if i == 0:
                cell.set_facecolor('#9b59b6')
                cell.set_text_props(weight='bold', color='white')
            else:
                cell.set_facecolor('#ecf0f1' if i % 2 == 0 else 'white')
    
    ax5.set_title('Model & Dataset Info', fontweight='bold', fontsize=12, pad=20)
    
    # Overall title
    fig.suptitle('LoRA Training Metrics Dashboard', 
                fontsize=16, fontweight='bold', y=0.98)
    
    plt.savefig('./lora-out/metrics_dashboard.png', dpi=300, bbox_inches='tight')
    print("✅ Saved: metrics_dashboard.png")
    plt.close()

def create_learning_curve(trainer_state):
    """Create learning curve with smoothing"""
    if not trainer_state or 'log_history' not in trainer_state:
        print("⚠️ No detailed training history available for learning curve")
        return
    
    log_history = trainer_state['log_history']
    
    # Extract data
    steps = []
    losses = []
    
    for entry in log_history:
        if 'loss' in entry:
            steps.append(entry['step'])
            losses.append(entry['loss'])
    
    if not steps:
        print("⚠️ No training loss data found")
        return
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plot raw data
    ax.plot(steps, losses, 'o', color=colors[0], alpha=0.3, markersize=4, label='Raw Loss')
    
    # Add smoothed curve if we have enough data
    if len(steps) > 5:
        # Simple moving average
        window = min(5, len(losses) // 3)
        smoothed = np.convolve(losses, np.ones(window)/window, mode='valid')
        smooth_steps = steps[window-1:]
        ax.plot(smooth_steps, smoothed, '-', color=colors[2], linewidth=2.5, 
               label=f'Smoothed (window={window})')
    
    ax.set_xlabel('Training Step', fontsize=12, fontweight='bold')
    ax.set_ylabel('Training Loss', fontsize=12, fontweight='bold')
    ax.set_title('Learning Curve - Training Loss Progression', fontsize=14, fontweight='bold', pad=20)
    ax.legend(fontsize=10, loc='upper right', framealpha=0.9)
    ax.grid(True, alpha=0.3)
    
    # Add trend arrow
    if len(losses) > 1:
        trend = "↓ Decreasing" if losses[-1] < losses[0] else "↑ Increasing"
        change = ((losses[-1] - losses[0]) / losses[0]) * 100
        ax.text(0.02, 0.98, f"Trend: {trend}\nChange: {change:+.1f}%",
               transform=ax.transAxes, fontsize=10,
               verticalalignment='top',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig('./lora-out/learning_curve.png', dpi=300, bbox_inches='tight')
    print("✅ Saved: learning_curve.png")
    plt.close()

def create_html_report(metrics, trainer_state):
    """Create an HTML report with all visualizations"""
    timestamp = metrics['timestamp']
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>LoRA Training Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 40px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 10px;
        }}
        .timestamp {{
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section h2 {{
            color: #34495e;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            color: white;
            text-align: center;
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        img {{
            max-width: 100%;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin: 20px 0;
        }}
        .status-good {{
            color: #27ae60;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 LoRA Training Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>
        
        <div class="section">
            <h2>📊 Key Metrics</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">Final Training Loss</div>
                    <div class="metric-value">{metrics['training_results']['final_loss']:.4f}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Final Eval Loss</div>
                    <div class="metric-value">{metrics['evaluation_results']['eval_loss']:.4f}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Total Samples</div>
                    <div class="metric-value">{metrics['dataset_info']['total_samples']}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Eval Speed</div>
                    <div class="metric-value">{metrics['evaluation_results']['eval_samples_per_second']:.1f}</div>
                    <div class="metric-label">samples/sec</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📈 Training Visualizations</h2>
            <h3>Metrics Dashboard</h3>
            <img src="metrics_dashboard.png" alt="Metrics Dashboard">
            
            <h3>Loss Progression</h3>
            <img src="loss_graph.png" alt="Loss Graph">
            
            <h3>Learning Curve</h3>
            <img src="learning_curve.png" alt="Learning Curve">
        </div>
        
        <div class="section">
            <h2>⚙️ Configuration</h2>
            <ul>
                <li><strong>Model:</strong> {metrics['model']}</li>
                <li><strong>Batch Size:</strong> {metrics['training_config']['batch_size']}</li>
                <li><strong>Learning Rate:</strong> {metrics['training_config']['learning_rate']}</li>
                <li><strong>Max Length:</strong> {metrics['training_config']['max_length']}</li>
                <li><strong>Gradient Accumulation:</strong> {metrics['training_config']['gradient_accumulation_steps']}</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>✅ Status</h2>
            <p class="status-good">Training completed successfully!</p>
            <p>Model saved to: <code>./lora-adapter/</code></p>
        </div>
    </div>
</body>
</html>
"""
    
    with open('./lora-out/training_report.html', 'w') as f:
        f.write(html_content)
    
    print("✅ Saved: training_report.html")

def main():
    """Main execution"""
    print("\n" + "="*60)
    print("📊 TRAINING METRICS VISUALIZATION")
    print("="*60 + "\n")
    
    # Load metrics
    metrics = load_metrics()
    if not metrics:
        return
    
    # Load detailed trainer state
    trainer_state = parse_trainer_state()
    
    # Generate visualizations
    print("\n🎨 Generating visualizations...\n")
    
    create_metrics_summary(metrics)
    create_loss_graph(metrics, trainer_state)
    create_learning_curve(trainer_state)
    create_html_report(metrics, trainer_state)
    
    print("\n" + "="*60)
    print("✅ All visualizations generated successfully!")
    print("="*60)
    print("\n📁 Output files:")
    print("   - metrics_dashboard.png")
    print("   - loss_graph.png")
    print("   - learning_curve.png")
    print("   - training_report.html")
    print("\n💡 Open training_report.html in your browser for interactive view!")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
