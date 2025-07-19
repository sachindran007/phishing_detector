import React, { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyze = async () => {
    if (!url) {
      setError('Please enter a URL.');
      return;
    }

    setIsLoading(true);
    setResults(null);
    setError('');

    try {
      // Correct HTTPS URL for the local backend
      const apiUrl = 'https://phishing-detector-backend.onrender.com/analyze'; 

      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        // This will catch backend errors but "Failed to fetch" happens before this
        const data = await response.json();
        throw new Error(data.error || 'An error occurred during analysis.');
      }
      
      const data = await response.json();
      setResults(data);
    } catch (err) {
      // The "Failed to fetch" error will be caught here
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };
  
  const getVerdictClass = (verdict = "") => {
    return `verdict-${verdict.toLowerCase().replace(/ /g, '-')}`;
  };

  return (
    <div className="App">
      <header>
        <h1>AI Phishing Detector</h1>
        <p>Enter a URL to get an instant, AI-powered security analysis.</p>
      </header>

      <main>
        <div className="analyzer-container">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
            placeholder="e.g., example.com"
          />
          <button onClick={handleAnalyze} disabled={isLoading}>
            {isLoading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {isLoading && (
          <div className="loading">
            <div className="spinner"></div>
            <p>Asking the AI...</p>
          </div>
        )}

        {results && (
          <div id="resultsContainer">
            <h2 id="verdict" className={getVerdictClass(results.verdict)}>
              {results.verdict}
            </h2>
            <p><strong>URL Checked:</strong> <span>{results.url}</span></p>
            <h3>Findings:</h3>
            <ul id="findingsList">
              {results.findings.length > 0 ? (
                results.findings.map((finding, index) => (
                  <li key={index}>
                    {finding.description}
                  </li>
                ))
              ) : (
                <li>No specific findings were returned.</li>
              )}
            </ul>
          </div>
        )}
      </main>

      <footer>
        <p>This tool uses AI for analysis. Always exercise caution when browsing.</p>
      </footer>
    </div>
  );
}

export default App;