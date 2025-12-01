// Simulation Interface JavaScript

// Threat Feed URLs
const FEEDS = {
    'feodo': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    'urlhaus': 'https://urlhaus.abuse.ch/downloads/text/',
    'phishtank': 'https://openphish.com/feed.txt' // Using OpenPhish for text format
};

// Update slider values
document.getElementById('size1').addEventListener('input', (e) => {
    document.getElementById('size1-value').textContent = e.target.value;
});

document.getElementById('size2').addEventListener('input', (e) => {
    document.getElementById('size2-value').textContent = e.target.value;
});

// Handle source changes
function updateSourceOptions(id) {
    const source = document.getElementById(`source${id}`).value;
    const iocTypeSelect = document.getElementById('ioc-type');

    // If both are synthetic, show IoC type selector
    const source1 = document.getElementById('source1').value;
    const source2 = document.getElementById('source2').value;

    if (source1 === 'synthetic' && source2 === 'synthetic') {
        iocTypeSelect.parentElement.style.display = 'block';
    } else {
        // If mixing real/synthetic, we should probably infer type or let user choose
        // For simplicity, if any real feed is selected, we might want to lock IoC type 
        // to match the feed, but since we support mixed, let's just keep it visible
        // or maybe hide it if both are real?
        // Let's keep it simple: always show, but maybe warn if mismatch?
        iocTypeSelect.parentElement.style.display = 'block';
    }
}

// Run simulation
document.getElementById('run-btn').addEventListener('click', async () => {
    const source1 = document.getElementById('source1').value;
    const source2 = document.getElementById('source2').value;

    const config = {
        source1: source1,
        source2: source2,
        feed1_url: FEEDS[source1],
        feed2_url: FEEDS[source2],
        ioc_type: document.getElementById('ioc-type').value,
        size1: parseInt(document.getElementById('size1').value),
        size2: parseInt(document.getElementById('size2').value),
        limit_size: document.getElementById('limit-size').checked,
        bloom_size: parseInt(document.getElementById('bloom-size').value),
        hash_count: parseInt(document.getElementById('hash-count').value),
        // Overlap is only relevant for synthetic generation
        overlap: 50
    };

    // Hide idle, show running
    document.getElementById('status-idle').style.display = 'none';
    document.getElementById('status-running').style.display = 'block';
    document.getElementById('status-complete').style.display = 'none';
    document.getElementById('run-btn').disabled = true;
    document.getElementById('run-btn').textContent = 'Running...';

    try {
        // Start simulation
        const response = await fetch('/api/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        const { sim_id } = await response.json();

        // Connect to SSE for status updates
        const eventSource = new EventSource(`/api/status/${sim_id}`);

        eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.keepalive) return;

            // Update progress
            if (data.progress !== undefined) {
                document.getElementById('progress-fill').style.width = data.progress + '%';
            }

            // Update stage indicators
            if (data.stage) {
                // Reset all stages
                document.querySelectorAll('.stage').forEach(s => {
                    s.classList.remove('active', 'complete');
                });

                // Mark stages as complete
                const stages = ['generating', 'encrypting', 'computing', 'complete'];
                const currentIndex = stages.indexOf(data.stage);

                stages.forEach((stage, index) => {
                    const el = document.getElementById(`stage-${stage}`);
                    if (index < currentIndex) {
                        el.classList.add('complete');
                    } else if (index === currentIndex) {
                        el.classList.add('active');
                    }
                });
            }

            // Add terminal output
            if (data.message) {
                const terminal = document.getElementById('terminal');
                const line = document.createElement('div');
                line.className = 'terminal-line';
                line.textContent = `[${new Date().toLocaleTimeString()}] ${data.message}`;
                terminal.appendChild(line);
                terminal.scrollTop = terminal.scrollHeight;
            }

            // Handle completion
            if (data.stage === 'complete') {
                eventSource.close();
                document.getElementById('status-running').style.display = 'none';
                document.getElementById('status-complete').style.display = 'block';
                document.getElementById('view-results-btn').href = `/results/${sim_id}`;
                document.getElementById('run-btn').disabled = false;
                document.getElementById('run-btn').textContent = '🚀 Run Simulation';
            }

            // Handle error
            if (data.stage === 'error') {
                eventSource.close();
                const terminal = document.getElementById('terminal');
                const line = document.createElement('div');
                line.className = 'terminal-line error';
                line.textContent = `ERROR: ${data.message}`;
                terminal.appendChild(line);
                document.getElementById('run-btn').disabled = false;
                document.getElementById('run-btn').textContent = '🚀 Run Simulation';
            }
        };

        eventSource.onerror = () => {
            eventSource.close();
            console.error('SSE connection error');
            document.getElementById('run-btn').disabled = false;
            document.getElementById('run-btn').textContent = '🚀 Run Simulation';
        };

    } catch (error) {
        console.error('Failed to start simulation:', error);
        alert('Failed to start simulation. Please try again.');
        document.getElementById('status-idle').style.display = 'block';
        document.getElementById('status-running').style.display = 'none';
        document.getElementById('run-btn').disabled = false;
        document.getElementById('run-btn').textContent = '🚀 Run Simulation';
    }
});
