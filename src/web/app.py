"""
Flask web application for PP-TIO Dashboard.
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import json
import time
import uuid
from datetime import datetime
from threading import Thread
import queue

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.data.dataset_loader import DatasetLoader
from src.computation.protocol import run_simulation

app = Flask(__name__)
CORS(app)

# Store simulation results and status
simulations = {}
simulation_queues = {}


class SimulationRunner:
    """Handles background simulation execution."""
    
    def __init__(self, sim_id, config):
        self.sim_id = sim_id
        self.config = config
        self.status_queue = queue.Queue()
        
    def run(self):
        """Execute simulation and update status."""
        try:
            # Update status: Generating datasets
            self.status_queue.put({
                'stage': 'generating',
                'message': 'Generating IoC datasets...',
                'progress': 25
            })
            
            # Generate or fetch datasets
            if self.config.get('source1') == 'synthetic' and self.config.get('source2') == 'synthetic':
                # Both synthetic: Use create_test_datasets to ensure overlap
                dataset1, dataset2 = DatasetLoader.create_test_datasets(
                    self.config.get('size1', 100),
                    self.config.get('size2', 100),
                    self.config.get('overlap', 50),
                    self.config.get('ioc_type', 'ip')
                )
            else:
                # Mixed or Real: Load independently
                if self.config.get('source1') == 'synthetic':
                    dataset1 = DatasetLoader.load_synthetic_dataset(
                        self.config.get('size1', 100), 
                        self.config.get('ioc_type', 'ip')
                    )
                else:
                    # Fetch real feed for dataset 1
                    url = self.config.get('feed1_url')
                    self.status_queue.put({
                        'stage': 'generating',
                        'message': f'Fetching Dataset 1 from {url}...',
                        'progress': 30
                    })
                    # Use auto-detection for real feeds
                    dataset1 = DatasetLoader.load_from_url(url, ioc_type=None)
                    if self.config.get('limit_size'):
                        dataset1 = dataset1[:self.config.get('size1', 100)]

                if self.config.get('source2') == 'synthetic':
                    dataset2 = DatasetLoader.load_synthetic_dataset(
                        self.config.get('size2', 100), 
                        self.config.get('ioc_type', 'ip')
                    )
                else:
                    # Fetch real feed for dataset 2
                    url = self.config.get('feed2_url')
                    self.status_queue.put({
                        'stage': 'generating',
                        'message': f'Fetching Dataset 2 from {url}...',
                        'progress': 40
                    })
                    # Use auto-detection for real feeds
                    dataset2 = DatasetLoader.load_from_url(url, ioc_type=None)
                    if self.config.get('limit_size'):
                        dataset2 = dataset2[:self.config.get('size2', 100)]
            
            # Update status: Encrypting
            self.status_queue.put({
                'stage': 'encrypting',
                'message': 'Encrypting Bloom filters...',
                'progress': 50
            })
            
            time.sleep(0.5)  # Brief pause for UI
            
            # Update status: Computing
            self.status_queue.put({
                'stage': 'computing',
                'message': 'Computing encrypted overlap...',
                'progress': 75
            })
            
            # Run simulation
            start_time = time.time()
            results = run_simulation(
                dataset1, dataset2,
                bloom_size=self.config.get('bloom_size', 10000),
                hash_count=self.config.get('hash_count', 5),
                verify=True
            )
            execution_time = time.time() - start_time
            
            # Add metadata
            results['execution_time'] = execution_time
            results['timestamp'] = datetime.now().isoformat()
            results['config'] = self.config
            
            # Update status: Complete
            self.status_queue.put({
                'stage': 'complete',
                'message': 'Simulation complete!',
                'progress': 100,
                'results': results
            })
            
            # Store results
            simulations[self.sim_id] = {
                'status': 'complete',
                'results': results,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.status_queue.put({
                'stage': 'error',
                'message': f'Error: {str(e)}',
                'progress': 0
            })
            simulations[self.sim_id] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html')


@app.route('/simulate')
def simulate_page():
    """Simulation interface."""
    return render_template('simulate.html')


@app.route('/results/<sim_id>')
def results_page(sim_id):
    """Results page."""
    if sim_id not in simulations:
        return "Simulation not found", 404
    return render_template('results.html', sim_id=sim_id)


@app.route('/api/run', methods=['POST'])
def run_simulation_api():
    """Start a new simulation."""
    config = request.json
    
    # Generate unique ID
    sim_id = str(uuid.uuid4())
    
    # Create status queue
    simulation_queues[sim_id] = queue.Queue()
    
    # Initialize simulation
    runner = SimulationRunner(sim_id, config)
    
    # Store initial status
    simulations[sim_id] = {
        'status': 'running',
        'config': config,
        'timestamp': datetime.now().isoformat()
    }
    
    # Run in background thread
    thread = Thread(target=runner.run)
    thread.daemon = True
    thread.start()
    
    # Store queue for SSE
    simulation_queues[sim_id] = runner.status_queue
    
    return jsonify({'sim_id': sim_id})


@app.route('/api/status/<sim_id>')
def simulation_status(sim_id):
    """Server-Sent Events stream for simulation status."""
    
    def generate():
        if sim_id not in simulation_queues:
            yield f"data: {json.dumps({'error': 'Simulation not found'})}\n\n"
            return
        
        status_queue = simulation_queues[sim_id]
        
        while True:
            try:
                # Get status update (blocking with timeout)
                status = status_queue.get(timeout=30)
                yield f"data: {json.dumps(status)}\n\n"
                
                # If complete or error, stop streaming
                if status['stage'] in ['complete', 'error']:
                    break
                    
            except queue.Empty:
                # Send keepalive
                yield f"data: {json.dumps({'keepalive': True})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/results/<sim_id>')
def get_results(sim_id):
    """Get simulation results."""
    if sim_id not in simulations:
        return jsonify({'error': 'Simulation not found'}), 404
    
    return jsonify(simulations[sim_id])


@app.route('/api/history')
def get_history():
    """Get simulation history."""
    history = []
    for sim_id, data in simulations.items():
        history.append({
            'id': sim_id,
            'timestamp': data.get('timestamp'),
            'status': data.get('status'),
            'config': data.get('config', {})
        })
    
    # Sort by timestamp (newest first)
    history.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify(history[:20])  # Return last 20


@app.route('/api/threat-feeds')
def get_threat_feeds():
    """List available threat intelligence feeds."""
    feeds = [
        {
            'id': 'feodo',
            'name': 'Feodo Tracker (abuse.ch)',
            'type': 'ip',
            'description': 'Botnet C2 IP addresses',
            'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
        },
        {
            'id': 'urlhaus',
            'name': 'URLhaus (abuse.ch)',
            'type': 'url',
            'description': 'Malware distribution URLs',
            'url': 'https://urlhaus.abuse.ch/downloads/text/'
        },
        {
            'id': 'phishing',
            'name': 'PhishTank',
            'type': 'url',
            'description': 'Phishing URLs',
            'url': 'https://data.phishtank.com/data/online-valid.json'
        }
    ]
    
    return jsonify(feeds)


@app.route('/api/stats')
def get_stats():
    """Get overall statistics."""
    total_sims = len(simulations)
    completed = sum(1 for s in simulations.values() if s['status'] == 'complete')
    
    # Calculate average accuracy
    accuracies = []
    for sim in simulations.values():
        if sim['status'] == 'complete' and 'results' in sim:
            if 'accuracy' in sim['results']:
                error_pct = sim['results']['accuracy']['error_percentage']
                accuracies.append(100 - error_pct)
    
    avg_accuracy = sum(accuracies) / len(accuracies) if accuracies else 0
    
    return jsonify({
        'total_simulations': total_sims,
        'completed': completed,
        'average_accuracy': round(avg_accuracy, 2),
        'privacy_preserved': 100.0  # Always 100%
    })


if __name__ == '__main__':
    print("🚀 Starting PP-TIO Web Dashboard...")
    print("📊 Open your browser to: http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)
