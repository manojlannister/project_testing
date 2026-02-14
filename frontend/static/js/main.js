/**
 * Sergent Scanner Core UI Logic
 * Handles real-time data fetching, progress tracking, and UI updates
 */

const Scanner = {
    // 1. Unified Fetcher for Backend API
    async fetchData(endpoint) {
        try {
            const response = await fetch(endpoint);
            if (!response.ok) throw new Error('Network response was not ok');
            return await response.json();
        } catch (error) {
            console.error('Scanner Error:', error);
            this.showToast("Connection to backend lost", "error");
        }
    },

    // 2. Trigger Scan and Update UI
    async runScan() {
        const consoleLog = document.getElementById('console-stream');
        const percentage = document.getElementById('percentage');
        const btn = document.getElementById('scanBtn');
        let progress = 0;

        // Visual feedback that the engine is starting
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="animate-spin inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full mr-2"></span> Initializing...';
        }

        try {
            const response = await fetch('/api/start-scan');
            
            if (!response.ok) throw new Error("Failed to connect to Scan API");

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const decodedChunk = decoder.decode(value, { stream: true });
                const lines = decodedChunk.split('\n');

                lines.forEach(line => {
                    if (line.trim()) {
                        this.appendConsole(line);
                        
                        // Increment progress bar: 10 steps total (+10 per line)
                        // This matches the updated app.py with Packet Analysis
                        progress += 10; 
                        if (progress > 98) progress = 98; // Prevent hitting 100 early
                        if (percentage) percentage.innerText = progress + "%";
                    }
                });
            }

            // Final state: 100% and Success
            if (percentage) percentage.innerText = "100%";
            if (btn) {
                btn.innerHTML = '<i data-lucide="check-circle" class="w-5 h-5"></i> Analysis Complete';
                btn.className = "flex-1 bg-emerald-600 text-white py-4 rounded-xl font-bold transition-all flex items-center justify-center gap-2";
                if (window.lucide) lucide.createIcons();
            }
            this.showToast("Analysis completed successfully", "success");

            // NEW: Auto-redirect to Packet Analysis dashboard after 3 seconds
            setTimeout(() => {
                window.location.href = "/vulnerabilities";
            }, 3000);

        } catch (error) {
            console.error('Scan Error:', error);
            this.appendConsole("CRITICAL ERROR: Scanning engine aborted.");
            this.showToast("Hardware connection failed", "error");
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i data-lucide="play" class="w-5 h-5"></i> Retry Analysis';
            }
        }
    },

    // 3. UI Helpers
    appendConsole(message) {
        const el = document.getElementById('console-stream');
        if (el) {
            const line = document.createElement('div');
            line.className = "mb-1 animate-in fade-in slide-in-from-left-2 duration-300";
            line.innerHTML = `<span class="text-blue-500 font-bold">>></span> ${message}`;
            el.appendChild(line);
            
            // Auto-scroll to bottom smoothly
            el.scrollTo({
                top: el.scrollHeight,
                behavior: 'smooth'
            });
        }
    },

    showToast(message, type = "info") {
        const colors = {
            error: "bg-red-600",
            success: "bg-emerald-600",
            info: "bg-blue-600"
        };
        
        const toast = document.createElement('div');
        toast.className = `fixed bottom-8 right-8 px-6 py-3 rounded-xl shadow-2xl ${colors[type] || colors.info} text-white text-sm font-bold z-[100] animate-bounce`;
        toast.innerText = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.remove('animate-bounce');
            toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
            setTimeout(() => toast.remove(), 500);
        }, 4000);
    }
};

// Auto-initialize icons on every page load
document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) {
        lucide.createIcons();
    }
});