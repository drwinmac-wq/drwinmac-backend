import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Resend } from "resend";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const resend = new Resend(process.env.RESEND_API_KEY);
function humanModelName(macModel) {
  if (macModel.startsWith("MacBookPro")) return "MacBook Pro (Intel-based)";
  if (macModel.startsWith("MacBookAir")) return "MacBook Air (Intel-based)";
  return macModel;
}

function readinessHeadline(tier) {
  switch (tier) {
    case "Well Positioned":
      return "Your system is well prepared for modern AI tools.";
    case "Ready":
      return "Your system can handle AI tools with some limitations.";
    case "Limited":
      return "Your system has notable limitations for AI workloads.";
    case "Not Ready":
      return "Your system is not prepared for modern AI workloads.";
    default:
      return "AI readiness assessment completed.";
  }
}

function urgencyNote(tier) {
  if (tier === "Not Ready" || tier === "Limited") {
    return "Waiting reduces your options and increases the likelihood of forced replacement.";
  }
  return "Planning ahead preserves flexibility and avoids rushed decisions.";
}

function buildClientEmail(scan) {
  return `
Your System Overview

We ran a system check on your Mac to understand how well it can support modern AI-powered software, productivity tools, and future macOS updates.

System snapshot:
- Mac model: ${humanModelName(scan.macModel)}
- Processor: ${scan.cpuBrand}
- Memory (RAM): ${scan.totalRAM} GB
- Storage type: ${scan.storageType}
- Free storage available: ${scan.freeStoragePercent}%

AI Readiness Result

Status: ${scan.aiPreparednessTier}

${readinessHeadline(scan.aiPreparednessTier)}

What This Means for You

- AI tools may run slowly or fail to run at all
- Performance issues are likely to increase over time
- Future software updates may reduce stability
- Acting early preserves options and flexibility

Why This Matters Now

${urgencyNote(scan.aiPreparednessTier)}

Recommended Next Steps

Many clients in your situation choose to review optimization, upgrade, or replacement options before problems escalate.

If you’d like help deciding what makes sense for you, just reply to this email.

— Dr.WinMac Tech Solutions
`;
}

function buildAdvisorEmail(scan) {
  return `
Client Summary

Email: ${scan.clientEmail}
Mac model: ${scan.macModel}
CPU: ${scan.cpuBrand}
RAM: ${scan.totalRAM} GB
Storage: ${scan.storageType}
Free storage: ${scan.freeStoragePercent}%

AI Preparedness Assessment

Overall Tier: ${scan.aiPreparednessTier}
Upgrade Ceiling: ${scan.upgradeCeiling}

Explanation:
${scan.aiPreparednessExplanation}

Sales Interpretation

- Intel mobile CPU with limited headroom
- Memory-constrained for AI workloads
- Weak upgrade ceiling
- Approaching end of practical usefulness for modern software

Recommended Action

Follow up within 24–48 hours while the result is fresh.

Suggested framing:
“Your Mac is still usable today, but it’s approaching a point where options become limited. I can help you decide the smartest path before that happens.”

Capacity Note

Single-operator business. Prioritize Not Ready and Limited tiers.
`;
}



app.post("/scan-results", async (req, res) => {
  try {
    const data = req.body || {};

    const clientEmail = String(data.clientEmail || data.email || "").trim();
    const isValidEmail = (email) =>
      /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);

    if (!isValidEmail(clientEmail)) {
      return res.status(400).json({
        success: false,
        error: "Missing or invalid client email"
      });
    }

    // Client email
    await resend.emails.send({
      from: "Dr.WinMac Scanner <scanner@drwinmac.tech>",
      to: clientEmail,
      subject: "Scan complete. Your results are being prepared.",
      text: buildClientEmail({
        ...data,
        clientEmail
      })
    });

    // Internal copy
    await resend.emails.send({
      from: "Dr.WinMac Scanner <scanner@drwinmac.tech>",
      to: "jeremy@drwinmac.tech",
      subject: `New scan received – ${data.aiPreparednessTier || "Assessment Complete"}`,
      text: buildAdvisorEmail({
        ...data,
        clientEmail
      })
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});


app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});


const PORT = 3000;


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});