async function loadDashboardData() {
    try {
        // Show loading state
        document.querySelectorAll('.card h2').forEach(el => {
            el.innerHTML = '<small><i class="bi bi-hourglass-split"></i> Loading...</small>';
        });
        
        // Get date range from inputs
        const startDate = document.getElementById('startDate').value;
        const endDate = document.getElementById('endDate').value;
        
        let url = '/api/dashboard_data';
        if (startDate && endDate) {
            url += `?start=${startDate}&end=${endDate}`;
        }
        
        const response = await fetch(url, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Dashboard data received:', data);
        
        // Update stats cards
        document.getElementById('totalCount').textContent = data.totalCount || 0;
        document.getElementById('normalCount').textContent = data.normalCount || 0;
        document.getElementById('dosCount').textContent = data.dosCount || 0;
        document.getElementById('probeCount').textContent = data.probeCount || 0;
        document.getElementById('u2rCount').textContent = data.u2rCount || 0;
        document.getElementById('r2lCount').textContent = data.r2lCount || 0;
        document.getElementById('unknownCount').textContent = data.unknownCount || 0;

        // Update last updated timestamp
        const lastUpdatedDate = new Date(data.lastUpdated);
        document.getElementById('lastUpdated').textContent = lastUpdatedDate.toLocaleString();
        
        
        // Update charts
        renderCharts(data);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        
        // Show error state
        document.querySelectorAll('.card h2').forEach(el => {
            if (el.innerHTML.includes('Loading')) {
                el.innerHTML = '<small class="text-danger"><i class="bi bi-exclamation-triangle"></i> Error</small>';
            }
        });
    }
}

// Call loadDashboardData after a successful upload
function handleUploadSuccess() {
    loadDashboardData();
}
