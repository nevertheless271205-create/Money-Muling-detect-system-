npm init -y
npm install express multer csv-parser
const express = require("express");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");

const app = express();
const upload = multer({ dest: "uploads/" });

/* ------------------------------
   Helper Functions
------------------------------ */

function parseTimestamp(ts) {
    return new Date(ts);
}

function buildGraph(transactions) {
    const graph = {};
    transactions.forEach(tx => {
        if (!graph[tx.sender_id]) graph[tx.sender_id] = [];
        graph[tx.sender_id].push(tx.receiver_id);
    });
    return graph;
}

/* ------------------------------
   Cycle Detection (DFS)
------------------------------ */

function detectCycles(graph) {
    const cycles = [];
    const nodes = Object.keys(graph);

    function dfs(start, current, visited, path) {
        visited.add(current);
        path.push(current);

        const neighbors = graph[current] || [];

        for (let neighbor of neighbors) {
            if (neighbor === start && path.length >= 3) {
                cycles.push([...path]);
            }
            if (!visited.has(neighbor)) {
                dfs(start, neighbor, visited, path);
            }
        }

        path.pop();
        visited.delete(current);
    }

    for (let node of nodes) {
        dfs(node, node, new Set(), []);
    }

    return cycles;
}

/* ------------------------------
   Fan In / Fan Out Detection
------------------------------ */

function detectFanInOut(transactions, threshold = 10) {
    const suspicious = {};
    const patterns = {};

    const accounts = [
        ...new Set(transactions.flatMap(t => [t.sender_id, t.receiver_id]))
    ];

    accounts.forEach(acc => {
        const incoming = transactions.filter(t => t.receiver_id === acc);
        const outgoing = transactions.filter(t => t.sender_id === acc);

        if (incoming.length >= threshold) {
            suspicious[acc] = (suspicious[acc] || 0) + 25;
            patterns[acc] = [...(patterns[acc] || []), "fan_in_smurfing"];
        }

        if (outgoing.length >= threshold) {
            suspicious[acc] = (suspicious[acc] || 0) + 25;
            patterns[acc] = [...(patterns[acc] || []), "fan_out_smurfing"];
        }
    });

    return { suspicious, patterns };
}

/* ------------------------------
   High Velocity Detection
------------------------------ */

function detectVelocity(transactions, threshold = 15) {
    const suspicious = {};
    const patterns = {};

    const accounts = [
        ...new Set(transactions.flatMap(t => [t.sender_id, t.receiver_id]))
    ];

    accounts.forEach(acc => {
        const related = transactions.filter(
            t => t.sender_id === acc || t.receiver_id === acc
        );

        if (related.length >= threshold) {
            suspicious[acc] = (suspicious[acc] || 0) + 15;
            patterns[acc] = [...(patterns[acc] || []), "high_velocity"];
        }
    });

    return { suspicious, patterns };
}

/* ------------------------------
   Main Fraud Processing Logic
------------------------------ */

function processTransactions(transactions) {

    const graph = buildGraph(transactions);
    const cycles = detectCycles(graph);

    let suspicionScores = {};
    let detectedPatterns = {};
    let fraudRings = [];
    let ringCounter = 1;
    let ringMap = {};

    // Cycle scoring + ring creation
    cycles.forEach(cycle => {
        const ringId = `RING_${String(ringCounter++).padStart(3, "0")}`;
        const uniqueMembers = [...new Set(cycle)];

        fraudRings.push({
            ring_id: ringId,
            member_accounts: uniqueMembers,
            pattern_type: "cycle",
            risk_score: Math.min(100, 70 + uniqueMembers.length * 5)
        });

        uniqueMembers.forEach(acc => {
            suspicionScores[acc] = (suspicionScores[acc] || 0) + 40;
            detectedPatterns[acc] = [
                ...(detectedPatterns[acc] || []),
                `cycle_length_${uniqueMembers.length}`
            ];
            ringMap[acc] = ringId;
        });
    });

    // Fan detection
    const fan = detectFanInOut(transactions);
    Object.assign(suspicionScores,
        Object.fromEntries(
            Object.entries(fan.suspicious).map(([k, v]) =>
                [k, (suspicionScores[k] || 0) + v])
        )
    );

    Object.entries(fan.patterns).forEach(([k, v]) => {
        detectedPatterns[k] = [...(detectedPatterns[k] || []), ...v];
    });

    // Velocity detection
    const velocity = detectVelocity(transactions);
    Object.assign(suspicionScores,
        Object.fromEntries(
            Object.entries(velocity.suspicious).map(([k, v]) =>
                [k, (suspicionScores[k] || 0) + v])
        )
    );

    Object.entries(velocity.patterns).forEach(([k, v]) => {
        detectedPatterns[k] = [...(detectedPatterns[k] || []), ...v];
    });

    // Cap scores at 100
    Object.keys(suspicionScores).forEach(acc => {
        suspicionScores[acc] = Math.min(100, suspicionScores[acc]);
    });

    const suspiciousAccounts = Object.keys(suspicionScores)
        .map(acc => ({
            account_id: acc,
            suspicion_score: suspicionScores[acc],
            detected_patterns: [...new Set(detectedPatterns[acc] || [])],
            ring_id: ringMap[acc] || "NONE"
        }))
        .sort((a, b) => b.suspicion_score - a.suspicion_score);

    return {
        suspicious_accounts: suspiciousAccounts,
        fraud_rings: fraudRings,
        summary: {
            total_accounts_analyzed: Object.keys(graph).length,
            suspicious_accounts_flagged: suspiciousAccounts.length,
            fraud_rings_detected: fraudRings.length
        }
    };
}

/* ------------------------------
   API Endpoint
------------------------------ */

app.post("/api/analyze", upload.single("file"), (req, res) => {

    const transactions = [];

    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on("data", (row) => transactions.push(row))
        .on("end", () => {

            const output = processTransactions(transactions);

            fs.unlinkSync(req.file.path);

            res.json(output);
        });
});

app.listen(3000, () => {
    console.log("🚀 Money Muling Detection Engine running on http://localhost:3000");
});
node server.js
