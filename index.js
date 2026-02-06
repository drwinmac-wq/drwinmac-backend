// server.js - Dr.WinMac Lead Generation Backend
import express from 'express';
import cors from 'cors';
import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json());

// ========== FLAG DETECTION & SCORING ==========

function analyzeScanResults(data) {
  const flags = [];
  let priorityScore = 0;
  let totalOpportunity = 0;

  // Battery Health Check
  if (data.batteryCapacity && data.batteryCapacity < 100) {
    const capacity = data.batteryCapacity;
    const cycles = data.batteryCycles || 0;
    
    if (capacity < 70 || cycles > 800) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Battery',
        issue: `Battery Health: ${capacity}% capacity, ${cycles} cycles`,
        recommendation: 'Battery replacement recommended',
        upsell: 'Battery replacement ($249)',
        value: 249,
        urgency: 'Address within 2-3 weeks to prevent unexpected shutdowns'
      });
      priorityScore += 3;
      totalOpportunity += 249;
    } else if (capacity < 85 || cycles > 500) {
      flags.push({
        severity: 'MODERATE',
        category: 'Battery',
        issue: `Battery Health: ${capacity}% capacity, ${cycles} cycles`,
        recommendation: 'Battery showing wear - monitor closely',
        upsell: 'Battery replacement ($249)',
        value: 249,
        urgency: 'Address within 1-2 months to maintain productivity'
      });
      priorityScore += 2;
      totalOpportunity += 249;
    }
  }

  // Backup Check
  if (data.lastBackupDate) {
    const backup = data.lastBackupDate;
    if (backup === 'Never') {
      flags.push({
        severity: 'CRITICAL',
        category: 'Data Protection',
        issue: 'No backup detected - data at risk',
        recommendation: 'Immediate backup solution required',
        upsell: 'Backup setup service ($149)',
        value: 149,
        urgency: 'Address immediately - one hardware failure away from total data loss'
      });
      priorityScore += 3;
      totalOpportunity += 149;
    } else if (backup !== 'Unknown') {
      // Try to parse date and check if old
      const daysOld = calculateDaysSinceBackup(backup);
      if (daysOld > 30) {
        flags.push({
          severity: 'MODERATE',
          category: 'Data Protection',
          issue: `Last backup: ${daysOld} days ago`,
          recommendation: 'Backup schedule needs attention',
          upsell: 'Backup setup service ($149)',
          value: 149,
          urgency: 'Address within 1-2 weeks to ensure data protection'
        });
        priorityScore += 2;
        totalOpportunity += 149;
      }
    }
  }

  // Firewall Check
  if (data.firewallEnabled === false) {
    flags.push({
      severity: 'CRITICAL',
      category: 'Security',
      issue: 'Firewall is DISABLED',
      recommendation: 'Enable firewall and perform security audit',
      upsell: 'Security audit ($149)',
      value: 149,
      urgency: 'Address within 3-5 days - system exposed to network threats'
    });
    priorityScore += 2;
    totalOpportunity += 149;
  }

  // FileVault Check
  if (data.fileVaultEnabled === false) {
    flags.push({
      severity: 'MODERATE',
      category: 'Security',
      issue: 'FileVault (disk encryption) is OFF',
      recommendation: 'Enable FileVault for data protection',
      upsell: 'Security audit ($149)',
      value: 149,
      urgency: 'Address within 2-3 weeks - data vulnerable if device is lost/stolen'
    });
    priorityScore += 1;
    totalOpportunity += 149;
  }

  // Storage Check
  if (data.freeStoragePercent !== undefined) {
    const freePercent = data.freeStoragePercent;
    if (freePercent < 10) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Storage',
        issue: `Storage critically low: ${freePercent}% free`,
        recommendation: 'Immediate storage upgrade or cleanup required',
        upsell: 'Storage upgrade consultation',
        value: 0,
        urgency: 'Address within 24-48 hours - system performance severely degraded'
      });
      priorityScore += 3;
    } else if (freePercent < 20) {
      flags.push({
        severity: 'MODERATE',
        category: 'Storage',
        issue: `Storage running low: ${freePercent}% free`,
        recommendation: 'Storage upgrade recommended soon',
        upsell: 'Storage upgrade consultation',
        value: 0,
        urgency: 'Address within 2-4 weeks to prevent performance issues'
      });
      priorityScore += 2;
    }
  }

  // Login Items Check
  if (data.loginItemsCount && data.loginItemsCount > 20) {
    flags.push({
      severity: 'MODERATE',
      category: 'Performance',
      issue: `${data.loginItemsCount} apps starting at boot`,
      recommendation: 'Performance optimization needed',
      upsell: 'Performance optimization service ($129)',
      value: 129,
      urgency: 'Address at your convenience to improve boot times'
    });
    priorityScore += 1;
    totalOpportunity += 129;
  }

  // Memory Pressure Check
  if (data.memoryPressure && data.memoryPressure !== 'Normal') {
    flags.push({
      severity: 'MODERATE',
      category: 'Performance',
      issue: `Memory pressure: ${data.memoryPressure}`,
      recommendation: 'RAM upgrade or memory optimization',
      upsell: 'Performance consultation',
      value: 0,
      urgency: 'Address within 3-4 weeks if experiencing slowdowns'
    });
    priorityScore += 1;
  }

  // Calculate priority level
  const criticalCount = flags.filter(f => f.severity === 'CRITICAL').length;
  const moderateCount = flags.filter(f => f.severity === 'MODERATE').length;
  
  let priorityLevel = 'COLD';
  if (criticalCount >= 2 || priorityScore >= 7) {
    priorityLevel = 'HOT';
  } else if (criticalCount >= 1 || priorityScore >= 4) {
    priorityLevel = 'WARM';
  }

  return {
    flags,
    priorityScore,
    priorityLevel,
    criticalCount,
    moderateCount,
    totalOpportunity,
    flagCount: flags.length
  };
}

function calculateDaysSinceBackup(backupDate) {
  try {
    const backup = new Date(backupDate);
    const now = new Date();
    const diffTime = Math.abs(now - backup);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  } catch {
    return 0;
  }
}

// ========== EMAIL GENERATION ==========

function generateClientEmail(data, analysis) {
  const { clientEmail, aiPreparednessTier, macModel, totalRAM, storageType } = data;
  const { flagCount, criticalCount, priorityLevel } = analysis;

  // Determine urgency message based on actual issues
  let urgencySection = '';
  const criticalFlags = analysis.flags.filter(f => f.severity === 'CRITICAL');
  
  if (criticalFlags.length > 0) {
    const urgencies = criticalFlags.map(f => f.urgency).filter(u => u);
    if (urgencies.length > 0) {
      urgencySection = `
        <div style="background: #fff3cd; border-left: 4px solid #cc6600; padding: 15px; margin: 20px 0;">
          <strong>⚠️ Attention Required:</strong>
          <p style="margin: 10px 0 0 0;">${urgencies[0]}</p>
        </div>
      `;
    }
  }

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
  
  <div style="text-align: center; padding: 20px 0; border-bottom: 2px solid #5b7db1;">
    <h1 style="color: #5b7db1; margin: 0;">Dr.WinMac's AI & System Check-Up</h1>
    <p style="color: #666; margin: 5px 0 0 0;">Your System Health Report</p>
  </div>

  <div style="padding: 30px 0;">
    <p>Hi there,</p>
    
    <p>Thank you for using our free Mac diagnostic tool! Your system scan is complete.</p>

    <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">Quick Summary</h3>
      <table style="width: 100%; border-collapse: collapse;">
        <tr>
          <td style="padding: 8px 0;"><strong>AI Readiness:</strong></td>
          <td style="padding: 8px 0;">${aiPreparednessTier || 'Ready'}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Mac Model:</strong></td>
          <td style="padding: 8px 0;">${macModel || 'Unknown'}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Memory:</strong></td>
          <td style="padding: 8px 0;">${totalRAM || 0} GB</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Storage:</strong></td>
          <td style="padding: 8px 0;">${storageType || 'Unknown'}</td>
        </tr>
      </table>
    </div>

    ${urgencySection}

    <div style="background: #e8f4f8; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">Optimization Opportunities</h3>
      <p>Our analysis identified <strong>${flagCount} area${flagCount !== 1 ? 's' : ''}</strong> where your Mac could benefit from attention${criticalCount > 0 ? `, including ${criticalCount} that ${criticalCount === 1 ? 'requires' : 'require'} prompt action` : ''}.</p>
      
      <p style="margin: 20px 0;">As a thank you for using our diagnostic tool, I'd like to extend a special offer:</p>
      
      <div style="background: white; border: 2px solid #cc6600; border-radius: 8px; padding: 20px; margin: 20px 0;">
        <p style="margin: 0 0 10px 0;"><strong>🎁 Complimentary Consultation Offer</strong></p>
        <p style="margin: 0;">Reply to this email within the next week for a <strong>free 15-minute consultation</strong> (normally $99) where we'll walk through your specific optimization opportunities and create a personalized action plan.</p>
      </div>
    </div>

    <div style="text-align: center; margin: 30px 0;">
      <a href="https://www.drwinmac.tech/services.html" style="display: inline-block; background: #cc6600; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; font-weight: bold;">View Our Services</a>
    </div>

    <p>Looking forward to helping you get the most out of your Mac!</p>
    
    <p>Best regards,<br>
    <strong>Jeremy</strong><br>
    Dr.WinMac<br>
    <a href="mailto:Jeremy@drwinmac.tech">Jeremy@drwinmac.tech</a></p>
  </div>

  <div style="border-top: 2px solid #eee; padding-top: 20px; margin-top: 30px; text-align: center; color: #999; font-size: 12px;">
    <p>© 2026 Dr.WinMac. All rights reserved.</p>
    <p><a href="https://www.drwinmac.tech" style="color: #5b7db1;">www.drwinmac.tech</a></p>
  </div>

</body>
</html>
  `;

  return html;
}

function generateInternalEmail(data, analysis) {
  const { clientEmail } = data;
  const { flags, priorityScore, priorityLevel, criticalCount, moderateCount, totalOpportunity } = analysis;

  const criticalFlags = flags.filter(f => f.severity === 'CRITICAL');
  const moderateFlags = flags.filter(f => f.severity === 'MODERATE');

  let flagsList = '';
  
  if (criticalFlags.length > 0) {
    flagsList += '<h3 style="color: #d32f2f;">⚠️ CRITICAL FLAGS (' + criticalFlags.length + '):</h3><ul>';
    criticalFlags.forEach(flag => {
      flagsList += `<li><strong>${flag.category}:</strong> ${flag.issue}`;
      if (flag.upsell) flagsList += ` → <strong>${flag.upsell}</strong>`;
      flagsList += `</li>`;
    });
    flagsList += '</ul>';
  }

  if (moderateFlags.length > 0) {
    flagsList += '<h3 style="color: #f57c00;">⚡ MODERATE FLAGS (' + moderateFlags.length + '):</h3><ul>';
    moderateFlags.forEach(flag => {
      flagsList += `<li><strong>${flag.category}:</strong> ${flag.issue}`;
      if (flag.upsell) flagsList += ` → <strong>${flag.upsell}</strong>`;
      flagsList += `</li>`;
    });
    flagsList += '</ul>';
  }

  // Generate call script dynamically based on flags
  let callScriptHook = 'Your scan results look great overall';
  if (criticalFlags.length > 0) {
    const topFlag = criticalFlags[0];
    callScriptHook = `I noticed ${topFlag.issue.toLowerCase()}. ${topFlag.recommendation}. Have you experienced any issues related to this?`;
  } else if (moderateFlags.length > 0) {
    const topFlag = moderateFlags[0];
    callScriptHook = `I saw ${topFlag.issue.toLowerCase()}. This is something we can help optimize. Have you noticed any performance concerns?`;
  }

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: 'Courier New', monospace; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
  
  <div style="background: #fff; border: 2px solid #5b7db1; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    <h1 style="margin: 0; color: #5b7db1;">🎯 NEW LEAD CAPTURED</h1>
    <p style="font-size: 18px; margin: 10px 0;"><strong>${clientEmail}</strong></p>
    <p style="margin: 5px 0;">Scan Date: ${new Date().toLocaleString()}</p>
    <p style="margin: 5px 0;">Mac: ${data.macModel || 'Unknown'} | Tier: ${data.aiPreparednessTier || 'Unknown'}</p>
  </div>

  <div style="background: ${priorityLevel === 'HOT' ? '#d32f2f' : priorityLevel === 'WARM' ? '#f57c00' : '#666'}; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
    <h2 style="margin: 0;">🚨 PRIORITY: ${priorityScore}/10 (${priorityLevel}${priorityLevel === 'HOT' ? ' - Route to Jeremy' : ''})</h2>
  </div>

  <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    ${flagsList}
    
    ${totalOpportunity > 0 ? `
    <div style="background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin-top: 20px;">
      <h3 style="margin: 0 0 10px 0; color: #2e7d32;">💰 TOTAL SERVICE OPPORTUNITY: $${totalOpportunity}+</h3>
    </div>
    ` : ''}
  </div>

  <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    <h2 style="margin-top: 0; color: #f57c00;">📞 QUICK CALL SCRIPT</h2>
    
    <p><strong>OPEN:</strong> "Hi there, this is [Your Name] from Dr.WinMac following up on the system scan you ran."</p>
    
    <p><strong>HOOK:</strong> "${callScriptHook}"</p>
    
    <p><strong>QUALIFY:</strong> "Is this Mac primarily for business or personal use?" → [Listen for pain points]</p>
    
    <p><strong>CLOSE:</strong> "Let me get you on Jeremy's calendar. I have [Day1] at [Time1] or [Day2] at [Time2] - which works better?"</p>
    
    <h3 style="color: #d32f2f;">OBJECTION HANDLING:</h3>
    <ul>
      <li><strong>"Too expensive"</strong> → "Most clients save 2+ hours/week after optimization. What's your time worth?"</li>
      <li><strong>"I'll do it myself"</strong> → "Totally respect that! Want our DIY guide? We're here if you get stuck."</li>
      <li><strong>"Need to think"</strong> → "Of course! What specific questions can I answer to help you decide?"</li>
      <li><strong>"Just had Apple look"</strong> → "Great! We specialize in optimization Apple doesn't cover. Did they mention [specific flag]?"</li>
    </ul>
  </div>

  <div style="background: #fff; border-radius: 8px; padding: 20px;">
    <h2 style="border-bottom: 2px solid #5b7db1; padding-bottom: 10px;">📊 FULL DIAGNOSTIC DUMP</h2>
    
    <h3>SYSTEM INFO:</h3>
    <ul>
      <li>macOS: ${data.osName || 'Unknown'} (${data.osVersion || 'Unknown'})</li>
      <li>Model: ${data.macModel || 'Unknown'}</li>
      <li>CPU: ${data.cpuBrand || 'Unknown'} (${data.physicalCores || 0} cores)</li>
      <li>RAM: ${data.totalRAM || 0} GB</li>
      <li>Storage: ${data.totalStorage || 0} GB ${data.storageType || ''} (${data.freeStoragePercent || 0}% free)</li>
      <li>GPU: ${data.gpuModel || 'Unknown'}</li>
    </ul>

    <h3>HEALTH METRICS:</h3>
    <ul>
      <li>Battery: ${data.batteryCapacity || 100}% capacity, ${data.batteryCycles || 0} cycles (${data.batteryCondition || 'N/A'})</li>
      <li>Last Backup: ${data.lastBackupDate || 'Unknown'}</li>
      <li>Firewall: ${data.firewallEnabled ? 'ON' : 'OFF'}</li>
      <li>FileVault: ${data.fileVaultEnabled ? 'ON' : 'OFF'}</li>
      <li>Login Items: ${data.loginItemsCount || 0} apps</li>
      <li>Memory Pressure: ${data.memoryPressure || 'Unknown'}</li>
      <li>Network: ${data.networkType || 'Unknown'}</li>
    </ul>

    <h3>AI PREPAREDNESS:</h3>
    <ul>
      <li>Tier: ${data.aiPreparednessTier || 'Unknown'}</li>
      <li>Explanation: ${data.aiPreparednessExplanation || 'N/A'}</li>
    </ul>
  </div>

  <div style="background: #e3f2fd; border-radius: 8px; padding: 20px; margin-top: 20px; text-align: center;">
    <a href="mailto:${clientEmail}" style="display: inline-block; background: #5b7db1; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px;">📧 Reply to Lead</a>
    <a href="https://calendly.com/drwinmac" style="display: inline-block; background: #cc6600; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px;">📅 Schedule Call</a>
  </div>

</body>
</html>
  `;

  return html;
}

// ========== API ENDPOINT ==========

app.post('/scan-results', async (req, res) => {
  try {
    const data = req.body;

    if (!data.clientEmail && !data.email) {
      return res.status(400).json({ error: 'Missing client email' });
    }

    const clientEmail = data.clientEmail || data.email;

    // Analyze scan results
    const analysis = analyzeScanResults(data);

    console.log(`📊 New scan from ${clientEmail} - Priority: ${analysis.priorityLevel} (${analysis.priorityScore}/10)`);
    console.log(`Flags: ${analysis.criticalCount} critical, ${analysis.moderateCount} moderate`);

    // Generate emails
    const clientEmailHTML = generateClientEmail(data, analysis);
    const internalEmailHTML = generateInternalEmail(data, analysis);

    // Send email to CLIENT
    const clientEmailResponse = await resend.emails.send({
      from: 'Dr.WinMac <noreply@drwinmac.tech>',
      to: clientEmail,
      subject: '✅ Your Mac Health Report - Dr.WinMac',
      html: clientEmailHTML
    });

    // Send email to YOU (Jeremy)
    const internalEmailResponse = await resend.emails.send({
      from: 'Dr.WinMac Leads <leads@drwinmac.tech>',
      to: 'Jeremy@drwinmac.tech',
      subject: `🎯 ${analysis.priorityLevel} LEAD: ${clientEmail} - $${analysis.totalOpportunity}+ opportunity`,
      html: internalEmailHTML
    });

    console.log('✅ Emails sent successfully');

    res.json({ 
      success: true,
      message: 'Scan results processed and emails sent',
      priority: analysis.priorityLevel,
      flagCount: analysis.flagCount,
      clientEmailId: clientEmailResponse.data?.id,
      internalEmailId: internalEmailResponse.data?.id
    });

  } catch (error) {
    console.error('❌ Error processing scan:', error);
    res.status(500).json({ 
      error: 'Failed to process scan results', 
      details: error.message 
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'drwinmac-backend', version: '2.0' });
});

// Fallback for old endpoint
app.post('/api/send-results', async (req, res) => {
  res.status(301).json({ 
    message: 'This endpoint has moved. Please use /scan-results instead.' 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Dr.WinMac Backend running on port ${PORT}`);
  console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? 'CONFIGURED' : 'MISSING API KEY'}`);
});
