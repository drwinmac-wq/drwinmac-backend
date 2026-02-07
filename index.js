// server.js - Velocity Strip-Search Backend
// Trust > Sales - Honest assessments build long-term relationships

import express from 'express';
import cors from 'cors';
import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json());

// ========== HONEST ANALYSIS & FLAG DETECTION ==========
// PRIORITY: HARDWARE upgrades (battery, RAM, storage, old systems) THEN security

function analyzeScanResults(data) {
  const flags = [];
  let priorityScore = 0;
  let totalOpportunity = 0;

  // === HARDWARE PRIORITY #1: OLD SYSTEM ===
  // Check for old Intel Macs (2015 and earlier) - HIGHEST PRIORITY
  // For old systems, we detail ALL the aging components
  if (data.macModel && data.cpuBrand) {
    const modelYear = extractYear(data.macModel);
    const isOldIntel = modelYear && modelYear <= 2015;
    
    if (isOldIntel) {
      // MAIN SYSTEM AGE FLAG
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware Age',
        clientFacing: `${modelYear} Mac - System approaching end of practical life`,
        issue: `System from ${modelYear} - multiple aging components`,
        recommendation: 'Replacement strongly recommended',
        upsell: 'New Mac consultation',
        value: 0
      });
      priorityScore += 4;
      
      // DETAILED COMPONENT FLAGS for old systems
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware Age',
        clientFacing: `Processor: ${data.cpuBrand?.substring(0, 30) || 'Intel Core'} - ${modelYear} generation CPU lacks modern instruction sets`,
        issue: `CPU from ${modelYear} - no support for modern AI/ML frameworks`,
        recommendation: 'Replacement required for AI workloads',
        upsell: null,
        value: 0
      });
      priorityScore += 2;
      
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware Age',
        clientFacing: `GPU: Integrated Intel graphics - Insufficient for AI processing`,
        issue: 'Integrated GPU from 2014-2015 generation',
        recommendation: 'External GPU or system replacement',
        upsell: null,
        value: 0
      });
      priorityScore += 2;
      
      // Note about soldered RAM for MacBookPro11,x models
      if (data.macModel.includes('MacBookPro11') || data.macModel.includes('MacBookAir')) {
        flags.push({
          severity: 'CRITICAL',
          category: 'Memory',
          clientFacing: `RAM: ${data.totalRAM}GB (soldered) - Cannot be upgraded on this model`,
          issue: `RAM soldered to logic board - upgrade impossible`,
          recommendation: 'System replacement required for more RAM',
          upsell: 'New Mac consultation',
          value: 0
        });
        priorityScore += 2;
      }
      
    } else if (modelYear && modelYear <= 2017) {
      flags.push({
        severity: 'MODERATE',
        category: 'Hardware Age',
        clientFacing: `${modelYear} Mac - Consider upgrade planning`,
        issue: `System from ${modelYear} - aging hardware`,
        recommendation: 'Plan for replacement within 1-2 years',
        upsell: 'Upgrade consultation',
        value: 0
      });
      priorityScore += 2;
    }
  }

  // === HARDWARE PRIORITY #2: BATTERY ===
  if (data.batteryCapacity && data.batteryCapacity < 100) {
    const capacity = data.batteryCapacity;
    const cycles = data.batteryCycles || 0;
    
    if (capacity < 70 || cycles > 1200) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Battery',
        clientFacing: `Battery: ${cycles} cycles (${capacity}% capacity) - replacement recommended`,
        issue: `Battery Health: ${capacity}% capacity, ${cycles} cycles`,
        recommendation: 'Battery replacement recommended',
        upsell: 'Battery replacement ($249)',
        value: 249
      });
      priorityScore += 3;
      totalOpportunity += 249;
    } else if (capacity < 85 || cycles > 800) {
      flags.push({
        severity: 'MODERATE',
        category: 'Battery',
        clientFacing: `Battery: ${cycles} cycles (${capacity}% capacity) - typical wear for age`,
        issue: `Battery Health: ${capacity}% capacity, ${cycles} cycles`,
        recommendation: 'Battery showing wear - monitor closely',
        upsell: 'Battery replacement ($249)',
        value: 249
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
        clientFacing: 'No backup detected - data at risk',
        issue: 'No backup detected - data at risk',
        recommendation: 'Immediate backup solution required',
        upsell: 'Backup setup service ($149)',
        value: 149
      });
      priorityScore += 3;
      totalOpportunity += 149;
    } else if (backup !== 'Unknown') {
      const daysOld = calculateDaysSinceBackup(backup);
      if (daysOld > 30) {
        flags.push({
          severity: 'MODERATE',
          category: 'Data Protection',
          clientFacing: `Last backup: ${daysOld} days ago`,
          issue: `Last backup: ${daysOld} days ago`,
          recommendation: 'Backup schedule needs attention',
          upsell: 'Backup setup service ($149)',
          value: 149
        });
        priorityScore += 2;
        totalOpportunity += 149;
      }
    }
  }

  // === SECURITY (LOWER PRIORITY) ===
  // Firewall Check - important but not as critical as hardware
  if (data.firewallEnabled === false) {
    flags.push({
      severity: 'MODERATE',  // Downgraded from CRITICAL
      category: 'Security',
      clientFacing: 'Firewall disabled - security vulnerability',
      issue: 'Firewall is DISABLED',
      recommendation: 'Enable firewall for network protection',
      upsell: 'Security audit ($99)',  // Lower price
      value: 99
    });
    priorityScore += 1;  // Reduced from 2
    totalOpportunity += 99;
  }

  // FileVault Check
  if (data.fileVaultEnabled === false) {
    flags.push({
      severity: 'INFO',  // Downgraded from MODERATE
      category: 'Security',
      clientFacing: 'Disk encryption is OFF',
      issue: 'FileVault (disk encryption) is OFF',
      recommendation: 'Consider enabling FileVault for data protection',
      upsell: 'Security setup ($79)',
      value: 79
    });
    priorityScore += 0;  // No priority bump for this
    totalOpportunity += 79;
  }

  // Storage Check
  if (data.freeStoragePercent !== undefined) {
    const freePercent = data.freeStoragePercent;
    if (freePercent < 10) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Storage',
        clientFacing: `Storage ${freePercent}% available - performance severely degraded`,
        issue: `Storage critically low: ${freePercent}% free`,
        recommendation: 'Immediate storage upgrade or cleanup required',
        upsell: 'Storage upgrade consultation',
        value: 0
      });
      priorityScore += 3;
    } else if (freePercent < 20) {
      flags.push({
        severity: 'MODERATE',
        category: 'Storage',
        clientFacing: `Storage ${freePercent}% available - recommend cleanup`,
        issue: `Storage running low: ${freePercent}% free`,
        recommendation: 'Storage upgrade recommended soon',
        upsell: 'Storage upgrade consultation',
        value: 0
      });
      priorityScore += 2;
    } else if (freePercent >= 50) {
      // Good storage - mention it positively
      flags.push({
        severity: 'POSITIVE',
        category: 'Storage',
        clientFacing: `Storage: ${freePercent}% available - good breathing room`,
        issue: 'Storage healthy',
        recommendation: 'No action needed',
        upsell: null,
        value: 0
      });
    }
  }

  // === HARDWARE PRIORITY #3: MEMORY (RAM) ===
  // RAM is critical for performance and AI workloads
  // Skip if already flagged as soldered in old system section
  if (data.totalRAM) {
    const ram = data.totalRAM;
    const pressure = data.memoryPressure || 'Normal';
    const modelYear = extractYear(data.macModel || '');
    const isSoldered = modelYear && modelYear <= 2015 && (data.macModel.includes('MacBookPro11') || data.macModel.includes('MacBookAir'));
    
    if (ram <= 8 && !isSoldered) {
      // Only flag RAM as upgradeable if it's NOT soldered
      flags.push({
        severity: 'CRITICAL',
        category: 'Memory',
        clientFacing: `${ram}GB RAM - insufficient for modern workloads`,
        issue: `Only ${ram}GB RAM - major bottleneck`,
        recommendation: 'RAM upgrade critical for performance',
        upsell: `RAM upgrade ($${ram <= 4 ? '200-400' : '150-300'})`,
        value: ram <= 4 ? 300 : 200
      });
      priorityScore += 3;  // HIGH PRIORITY
      totalOpportunity += (ram <= 4 ? 300 : 200);
    } else if (ram < 16 && pressure !== 'Normal' && !isSoldered) {
      flags.push({
        severity: 'MODERATE',
        category: 'Memory',
        clientFacing: `${ram}GB RAM with ${pressure.toLowerCase()} memory pressure`,
        issue: `${ram}GB RAM under pressure`,
        recommendation: 'RAM upgrade recommended for smooth performance',
        upsell: 'RAM upgrade ($150-250)',
        value: 200
      });
      priorityScore += 2;
      totalOpportunity += 200;
    } else if (ram >= 16 && pressure === 'Normal') {
      flags.push({
        severity: 'POSITIVE',
        category: 'Memory',
        clientFacing: `Memory: ${ram}GB - good for most tasks`,
        issue: 'Memory adequate',
        recommendation: 'No action needed',
        upsell: null,
        value: 0
      });
    }
  }

  // Login Items Check
  if (data.loginItemsCount && data.loginItemsCount > 20) {
    flags.push({
      severity: 'MODERATE',
      category: 'Performance',
      clientFacing: `${data.loginItemsCount} apps starting at boot - slowing startup`,
      issue: `${data.loginItemsCount} apps starting at boot`,
      recommendation: 'Performance optimization needed',
      upsell: 'Performance optimization service ($129)',
      value: 129
    });
    priorityScore += 1;
    totalOpportunity += 129;
  }

  // Software Update Check - Service Opportunity
  if (data.softwareUpdateStatus === 'Check manually') {
    flags.push({
      severity: 'MODERATE',
      category: 'Maintenance',
      clientFacing: 'Software updates not configured for automatic installation',
      issue: 'Manual update configuration - likely outdated system',
      recommendation: 'Enable automatic updates and install pending updates',
      upsell: 'System update & optimization service ($149)',
      value: 149
    });
    priorityScore += 1;
    totalOpportunity += 149;
  }

  // Add replacement consultation value for old systems
  const modelYear = extractYear(data.macModel || '');
  if (modelYear && modelYear <= 2015) {
    totalOpportunity += 150;  // Consultation fee for replacement guidance
  }

  // CPU/Architecture Assessment (for AI readiness)
  if (data.architecture && data.cpuBrand) {
    const isIntel = data.architecture.toLowerCase().includes('x86') || data.architecture.toLowerCase().includes('intel');
    const isOldIntel = isIntel && (data.cpuBrand.includes('2015') || data.cpuBrand.includes('2016') || data.cpuBrand.includes('2014'));
    
    if (isOldIntel) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware',
        clientFacing: `Intel CPU (${data.cpuBrand.includes('2015') ? '2015' : 'older'}) - approaching end of software support`,
        issue: 'Old Intel CPU approaching end of life',
        recommendation: 'Replacement recommended for AI workloads',
        upsell: 'Upgrade consultation',
        value: 0
      });
      priorityScore += 2;
    }
  }

  // Software Update Check
  if (data.softwareUpdateStatus && data.softwareUpdateStatus !== 'Up to date' && data.softwareUpdateStatus !== 'Unknown') {
    const updateCount = parseInt(data.softwareUpdateStatus) || 0;
    if (updateCount > 0) {
      flags.push({
        severity: 'MODERATE',
        category: 'Software',
        clientFacing: `${data.softwareUpdateStatus} pending`,
        issue: `${data.softwareUpdateStatus} pending`,
        recommendation: 'Install available updates for security and performance',
        upsell: 'System maintenance service ($129)',
        value: 129
      });
      priorityScore += 1;
      totalOpportunity += 129;
    }
  }

  // WiFi Signal Check
  if (data.wifiSignalStrength && (data.wifiSignalStrength === 'Weak' || data.wifiSignalStrength === 'Fair')) {
    flags.push({
      severity: 'MODERATE',
      category: 'Network',
      clientFacing: `WiFi signal: ${data.wifiSignalStrength} - may impact performance`,
      issue: `WiFi signal strength: ${data.wifiSignalStrength}`,
      recommendation: 'Network optimization or router upgrade recommended',
      upsell: 'Network assessment ($99)',
      value: 99
    });
    priorityScore += 1;
    totalOpportunity += 99;
  }

  // RAM Speed Check (for older Intel Macs)
  if (data.ramSpeed && data.ramSpeed > 0 && data.ramSpeed < 2400) {
    const isIntel = data.architecture && (data.architecture.toLowerCase().includes('x86') || data.architecture.toLowerCase().includes('intel'));
    if (isIntel) {
      flags.push({
        severity: 'MODERATE',
        category: 'Performance',
        clientFacing: `RAM speed: ${data.ramSpeed}MHz - slower than modern standards`,
        issue: `RAM Speed: ${data.ramSpeed}MHz (slow)`,
        recommendation: 'RAM upgrade for faster performance',
        upsell: 'RAM upgrade consultation',
        value: 0
      });
      priorityScore += 1;
    }
  }

  // External Monitor Assessment (positive note)
  if (data.externalMonitors && data.externalMonitors > 0) {
    flags.push({
      severity: 'POSITIVE',
      category: 'Display',
      clientFacing: `Using ${data.externalMonitors} external monitor${data.externalMonitors > 1 ? 's' : ''} - good productivity setup`,
      issue: 'External monitors detected',
      recommendation: 'No action needed',
      upsell: null,
      value: 0
    });
  }

  // Calculate priority level and system health
  const criticalCount = flags.filter(f => f.severity === 'CRITICAL').length;
  const moderateCount = flags.filter(f => f.severity === 'MODERATE').length;
  const positiveCount = flags.filter(f => f.severity === 'POSITIVE').length;
  
  let priorityLevel = 'COLD';
  let systemHealth = 'GOOD';
  
  if (criticalCount >= 3 || priorityScore >= 8) {
    priorityLevel = 'HOT';
    systemHealth = 'CRITICAL';
  } else if (criticalCount >= 2 || priorityScore >= 6) {
    priorityLevel = 'WARM';
    systemHealth = 'NEEDS_ATTENTION';
  } else if (criticalCount >= 1 || priorityScore >= 4) {
    priorityLevel = 'WARM';
    systemHealth = 'MODERATE';
  } else if (positiveCount >= 2 && moderateCount <= 1) {
    systemHealth = 'EXCELLENT';
  }

  return {
    flags,
    priorityScore,
    priorityLevel,
    systemHealth,
    criticalCount,
    moderateCount,
    positiveCount,
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

function extractYear(macModel) {
  // Extract year from model identifiers like "MacBookPro11,3" or from cpuBrand
  const yearMatch = macModel.match(/20\d{2}/);
  if (yearMatch) {
    return parseInt(yearMatch[0]);
  }
  
  // Fallback: try to infer from model number
  if (macModel.includes('MacBookPro11') || macModel.includes('MacBookAir7')) return 2014;
  if (macModel.includes('MacBookPro12') || macModel.includes('MacBookAir7')) return 2015;
  if (macModel.includes('MacBookPro13') || macModel.includes('MacBookAir8')) return 2016;
  
  return null;
}

// ========== HONEST TIMELINE GENERATION ==========

function generateTimeline(analysis, data) {
  const { systemHealth, criticalCount } = analysis;
  
  switch (systemHealth) {
    case 'EXCELLENT':
      return {
        assessment: 'Your Mac is in excellent shape and should serve you well for 2-3+ years.',
        proTip: 'Regular maintenance (battery calibration, storage optimization, security updates) can extend your Mac\'s productive life even further. We offer quarterly tune-ups to keep you ahead of issues - reply if you\'d like details.'
      };
      
    case 'GOOD':
      return {
        assessment: 'Your Mac is in good condition and should serve you well for 1-2+ years with attention to the items noted above.',
        proTip: 'Regular maintenance can extend your system\'s lifespan and prevent small issues from becoming expensive problems. We offer quarterly check-ups - reply to learn more.'
      };
      
    case 'MODERATE':
      return {
        assessment: 'Address the noted items within 2-3 months to prevent workflow disruption.',
        proTip: 'Acting now preserves your options and avoids emergency situations. We can help you prioritize which fixes deliver the most value first - reply to discuss your best path forward.'
      };
      
    case 'NEEDS_ATTENTION':
      return {
        assessment: 'Address the critical items within 4-6 weeks to maintain productivity.',
        proTip: 'These issues will worsen over time. We can help you create a cost-effective action plan that addresses the most urgent items first - reply to explore your options.'
      };
      
    case 'CRITICAL':
      return {
        assessment: 'Immediate attention recommended. Plan upgrade or replacement within 4-6 weeks.',
        proTip: 'Waiting risks data loss and forced last-minute decisions. We can help you evaluate whether targeted upgrades or replacement makes more sense for your situation - reply to explore your options.'
      };
      
    default:
      return {
        assessment: 'Your system assessment is complete.',
        proTip: 'We\'re here if you have questions about optimizing your Mac\'s performance.'
      };
  }
}

// ========== HELPER FUNCTIONS FOR CLIENT EMAIL ==========

function getUrgencyTimeline(flag) {
  if (flag.severity === 'CRITICAL') {
    if (flag.category === 'Hardware Age') return 'Replace within 3-6 months';
    if (flag.category === 'Battery') return 'Address within 2-4 weeks';
    if (flag.category === 'Memory') return 'Upgrade within 1-2 months';
    if (flag.category === 'Storage') return 'Address within 1-2 weeks';
    if (flag.category === 'Data Protection') return 'Set up immediately';
    return 'Address within 2-4 weeks';
  }
  if (flag.severity === 'MODERATE') {
    if (flag.category === 'Battery') return 'Plan replacement within 6-12 months';
    if (flag.category === 'Memory') return 'Consider upgrade within 3-6 months';
    if (flag.category === 'Storage') return 'Clean up or upgrade within 1-2 months';
    if (flag.category === 'Security') return 'Enable within 1 month';
    return 'Address within 2-3 months';
  }
  return '';
}

function calculateSystemGrade(analysis, data) {
  const { priorityScore, criticalCount, moderateCount } = analysis;
  const { totalRAM } = data;
  
  let grade = 'B';
  let color = '#4caf50';
  let proTip = 'Your system is performing well. Regular maintenance will keep it running smoothly.';
  
  // Grading logic with HONEST, GROUNDED pro tips
  if (priorityScore >= 12 || criticalCount >= 4) {
    grade = 'D-';
    color = '#c62828';
    proTip = 'Your Mac has reached the point where replacement makes more financial sense than continued repairs. Modern software requirements are outpacing what this hardware can deliver.';
  } else if (priorityScore >= 10 || criticalCount >= 3) {
    grade = 'D+';
    color = '#d32f2f';
    proTip = 'This system is nearing the end of its practical lifespan. Budget for replacement within 3-6 months to avoid being forced into a last-minute decision.';
  } else if (priorityScore >= 7 || criticalCount >= 2) {
    grade = 'C-';
    color = '#f57c00';
    proTip = 'Multiple hardware limitations are affecting your productivity. Address the critical items first, but start planning for eventual replacement.';
  } else if (priorityScore >= 5 || criticalCount >= 1) {
    grade = 'C+';
    color = '#ffa726';
    proTip = 'Your system will continue working for everyday tasks, but upgrading or replacing within 6-12 months will prevent workflow disruptions.';
  } else if (priorityScore >= 3 || moderateCount >= 2) {
    grade = 'B-';
    color = '#66bb6a';
    proTip = 'A few minor improvements will extend your system\'s useful life. Addressing these proactively is cheaper than waiting for problems.';
  } else if (priorityScore >= 1) {
    grade = 'B+';
    color = '#43a047';
    proTip = 'Solid system overall. Regular backups and maintenance will keep you running smoothly for years.';
  } else if (totalRAM >= 16) {
    grade = 'A';
    color = '#2e7d32';
    proTip = 'Excellent hardware configuration. Focus on data protection and you\'re set for the long haul.';
  }
  
  // A+ reserved for near-perfect systems
  if (priorityScore === 0 && criticalCount === 0 && moderateCount === 0 && totalRAM >= 32) {
    grade = 'A+';
    color = '#1b5e20';
    proTip = 'Outstanding system with professional-grade specs. Maintain your current backup and security practices.';
  }
  
  return { letter: grade, color, proTip };
}

// ========== CLIENT EMAIL GENERATION ==========

function generateClientEmail(data, analysis) {
  const { clientName, clientEmail, macModel, totalRAM, storageType, cpuBrand, totalStorage, freeStoragePercent } = data;
  const { flags, systemHealth } = analysis;

  // Separate hardware issues (CRITICAL/MODERATE) and service issues
  const hardwareIssues = flags.filter(f => 
    (f.severity === 'CRITICAL' || f.severity === 'MODERATE') && 
    (f.category === 'Hardware Age' || f.category === 'Memory' || f.category === 'Battery' || f.category === 'Storage')
  ).slice(0, 5);
  
  const serviceIssues = flags.filter(f => 
    f.category === 'Data Protection' || f.category === 'Security' || f.category === 'Performance'
  ).slice(0, 3);
  
  const additionalHardware = flags.filter(f => 
    (f.severity === 'CRITICAL' || f.severity === 'MODERATE') && 
    (f.category === 'Hardware Age' || f.category === 'Memory' || f.category === 'Battery' || f.category === 'Storage')
  ).length - 5;

  // Build hardware issues list with urgency
  let hardwareList = '';
  if (hardwareIssues.length > 0) {
    hardwareIssues.forEach((flag, index) => {
      const urgency = getUrgencyTimeline(flag);
      hardwareList += `<li style="margin: 10px 0;"><strong>${flag.clientFacing}</strong>${urgency ? `<br><span style="color: #666; font-size: 14px;">Timeline: ${urgency}</span>` : ''}</li>`;
    });
    if (additionalHardware > 0) {
      hardwareList += `<li style="margin: 10px 0; font-style: italic; color: #666;">+ ${additionalHardware} additional hardware concern${additionalHardware === 1 ? '' : 's'} identified</li>`;
    }
  } else {
    hardwareList = '<li style="margin: 10px 0;">No critical hardware issues detected</li>';
  }

  // Build service issues list
  let serviceList = '';
  if (serviceIssues.length > 0) {
    serviceIssues.forEach((flag, index) => {
      const urgency = getUrgencyTimeline(flag);
      serviceList += `<li style="margin: 10px 0;"><strong>${flag.clientFacing}</strong>${urgency ? `<br><span style="color: #666; font-size: 14px;">Timeline: ${urgency}</span>` : ''}</li>`;
    });
  } else {
    serviceList = '<li style="margin: 10px 0;">System maintenance up to date</li>';
  }

  // Calculate overall grade
  const grade = calculateSystemGrade(analysis, data);

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
  
  <div style="text-align: center; padding: 20px 0; border-bottom: 2px solid #5b7db1;">
    <h1 style="color: #5b7db1; margin: 0;">Velocity Strip-Search</h1>
    <p style="color: #666; margin: 5px 0 0 0;">Hardware Analysis Report</p>
  </div>

  <div style="padding: 30px 0;">
    <p>${clientName ? `Hi ${clientName.charAt(0).toUpperCase() + clientName.slice(1)},` : 'Hello,'}</p>
    <p>Your comprehensive hardware scan is complete. Here's what we found:</p>

    <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">Quick Summary</h3>
      <table style="width: 100%; border-collapse: collapse;">
        <tr>
          <td style="padding: 8px 0;"><strong>Mac Model:</strong></td>
          <td style="padding: 8px 0;">${macModel || 'Unknown'}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Processor:</strong></td>
          <td style="padding: 8px 0;">${cpuBrand || 'Unknown'}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Memory (RAM):</strong></td>
          <td style="padding: 8px 0;">${totalRAM || 0} GB</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Storage:</strong></td>
          <td style="padding: 8px 0;">${totalStorage || 0} GB ${storageType || ''} (${freeStoragePercent || 0}% free)</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Overall AI Preparedness Grade:</strong></td>
          <td style="padding: 8px 0; font-size: 18px;"><strong style="color: ${grade.color};">${grade.letter}</strong></td>
        </tr>
      </table>
      
      <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ddd;">
        <h4 style="margin: 0 0 10px 0; color: #5b7db1; font-size: 14px;">Key Health Metrics:</h4>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px;">
          <div><strong>Battery:</strong> ${data.batteryCapacity || 0}% (${data.batteryCycles || 0} cycles)</div>
          <div><strong>Last Backup:</strong> ${data.lastBackupDate ? new Date(data.lastBackupDate).toLocaleDateString() : 'Never'}</div>
          <div><strong>Firewall:</strong> ${data.firewallEnabled ? 'ON' : 'OFF'}</div>
          <div><strong>Disk Encryption:</strong> ${data.fileVaultEnabled ? 'ON' : 'OFF'}</div>
          <div><strong>Software Updates:</strong> ${data.softwareUpdateStatus || 'Unknown'}</div>
          <div><strong>Memory Pressure:</strong> ${data.memoryPressure || 'Unknown'}</div>
        </div>
      </div>
    </div>

    <div style="background: #fff3cd; border-left: 4px solid #cc6600; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #cc6600;">⚠️ Attention Required - Hardware</h3>
      <ul style="margin: 10px 0; padding-left: 20px;">${hardwareList}</ul>
    </div>

    <div style="background: #e8f4f8; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">Optimization Opportunities - Services</h3>
      <ul style="margin: 10px 0; padding-left: 20px;">${serviceList}</ul>
    </div>

    <div style="background: #f0f0f0; border-radius: 8px; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Pro tip:</strong> ${grade.proTip}</p>
    </div>

    <div style="text-align: center; margin: 30px 0;">
      <a href="https://www.drwinmac.tech/services.html" style="display: inline-block; background: #cc6600; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; font-weight: bold;">Schedule Free Consultation</a>
    </div>

    <p>Questions about your results? Just reply to this email.</p>
    
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

// ========== INTERNAL EMAIL (unchanged from before) ==========

function generateInternalEmail(data, analysis) {
  const { clientName, clientEmail } = data;
  const { flags, priorityScore, priorityLevel, criticalCount, moderateCount, totalOpportunity, systemHealth } = analysis;

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

  let callScriptHook = 'Your scan results look great overall';
  if (criticalFlags.length > 0) {
    const topFlag = criticalFlags[0];
    callScriptHook = `I noticed ${topFlag.issue.toLowerCase()}. ${topFlag.recommendation}. Have you experienced any issues related to this?`;
  } else if (moderateFlags.length > 0) {
    const topFlag = moderateFlags[0];
    callScriptHook = `I saw ${topFlag.issue.toLowerCase()}. This is something we can help optimize. Have you noticed any performance concerns?`;
  }

  const timeline = generateTimeline(analysis, data);

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
    <p style="font-size: 18px; margin: 10px 0;"><strong>${clientName || 'Name not provided'}</strong></p>
    <p style="font-size: 18px; margin: 10px 0;"><strong>${clientEmail}</strong></p>
    <p style="margin: 5px 0;">Scan Date: ${new Date().toLocaleString()}</p>
    <p style="margin: 5px 0;">Mac: ${data.macModel || 'Unknown'} | Tier: ${data.aiPreparednessTier || 'Unknown'}</p>
    <p style="margin: 5px 0;">System Health: <strong>${systemHealth}</strong></p>
  </div>

  <div style="background: ${priorityLevel === 'HOT' ? '#d32f2f' : priorityLevel === 'WARM' ? '#f57c00' : '#666'}; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
    <h2 style="margin: 0;">🚨 PRIORITY: ${priorityScore}/10 (${priorityLevel}${priorityLevel === 'HOT' ? ' - Route to Jeremy' : ''})</h2>
  </div>

  <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    ${flagsList || '<p>No critical issues detected - system in good health.</p>'}
    
    ${totalOpportunity > 0 ? `
    <div style="background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin-top: 20px;">
      <h3 style="margin: 0 0 10px 0; color: #2e7d32;">💰 TOTAL SERVICE OPPORTUNITY: $${totalOpportunity}+</h3>
    </div>
    ` : ''}
    
    <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin-top: 20px;">
      <h4 style="margin: 0 0 5px 0;">TIMELINE GIVEN TO CLIENT:</h4>
      <p style="margin: 5px 0;">${timeline.assessment}</p>
      <p style="margin: 5px 0; font-style: italic;">"Pro tip: ${timeline.proTip}"</p>
    </div>
  </div>

  <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
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
      <li>Last Backup: ${data.lastBackupDate || 'Never'}</li>
      <li>Firewall: ${data.firewallEnabled ? 'ON' : 'OFF'}</li>
      <li>FileVault: ${data.fileVaultEnabled ? 'ON' : 'OFF'}</li>
      <li>SIP (System Integrity Protection): ${data.sipEnabled ? 'ON' : 'OFF'}</li>
      <li>Software Updates: ${data.softwareUpdateStatus || 'Unknown'}</li>
      <li>Login Items: ${data.loginItemsCount || 0} apps</li>
      <li>Memory Pressure: ${data.memoryPressure || 'Unknown'}</li>
      <li>RAM Speed: ${data.ramSpeed || 0} MHz</li>
      <li>Network: ${data.networkType || 'Unknown'}</li>
      <li>WiFi Signal: ${data.wifiSignalStrength || 'Unknown'}</li>
      <li>Display: ${data.displayResolution || 'Unknown'}</li>
      <li>External Monitors: ${data.externalMonitors || 0}</li>
      <li>CPU Temperature: ${data.cpuTemperature || 0}°C${data.cpuTemperature > 0 ? '' : ' (unavailable)'}</li>
    </ul>

    <h3>AI PREPAREDNESS:</h3>
    <ul>
      <li>Tier: ${data.aiPreparednessTier || 'Unknown'}</li>
      <li>System Health: ${systemHealth}</li>
    </ul>
  </div>

  <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    <h2 style="margin-top: 0; color: #f57c00;">📞 SALES CALL SCRIPT</h2>
    
    <h3 style="color: #5b7db1; margin-top: 0;">PRE-CALL PREP:</h3>
    <ul style="margin-bottom: 20px;">
      <li><strong>Review flagged issues above</strong> - Know the top 2-3 pain points</li>
      <li><strong>Check their grade:</strong> ${systemHealth} system</li>
      <li><strong>Total opportunity:</strong> $${totalOpportunity} in services</li>
      <li><strong>Decision timeline:</strong> ${criticalCount >= 2 ? 'URGENT - 2-4 weeks' : moderateCount >= 2 ? 'Soon - 1-2 months' : 'Planning - 3-6 months'}</li>
    </ul>
    
    <h3 style="color: #5b7db1;">OPENING (First 30 seconds):</h3>
    <p><strong>YOU:</strong> "Hi ${clientName || '[Name]'}, this is [Your Name] from Dr.WinMac. You ran our Velocity Strip-Search scan on your ${data.macModel || 'Mac'} - do you have a couple minutes to go over what we found?"</p>
    <p style="font-size: 12px; color: #666;"><em>[Wait for confirmation. If busy: "No problem, when's a better time? I have the results in front of me."]</em></p>
    
    <h3 style="color: #5b7db1;">HOOK (Lead with their top issue):</h3>
    <p><strong>YOU:</strong> "${callScriptHook}"</p>
    <p style="font-size: 12px; color: #666;"><em>[Pause. Let them respond. Listen for frustration, workflow impacts, or urgency.]</em></p>
    
    <h3 style="color: #5b7db1;">QUALIFY (Understand their world):</h3>
    <p><strong>YOU:</strong> "Quick question - is this Mac primarily for work, personal use, or both?"</p>
    <p style="font-size: 12px; color: #666;"><em>[If work: "What kind of work?" / If personal: "What do you mainly use it for?"]</em></p>
    <p><strong>FOLLOW-UP:</strong> "On a scale of 1-10, how much is [issue from hook] slowing you down day-to-day?"</p>
    <p style="font-size: 12px; color: #666;"><em>[Listen for 7+: that's real pain. Under 5: deprioritize.]</em></p>
    
    <h3 style="color: #5b7db1;">PRESENT SOLUTION:</h3>
    <p><strong>YOU:</strong> "Based on what you're telling me, here's what I'd recommend..."</p>
    <ul style="margin-top: 10px;">
      <li><strong>If ${systemHealth === 'CRITICAL' || systemHealth === 'NEEDS_ATTENTION' ? 'critical issues' : 'multiple flags'}:</strong> "Let's get you on Jeremy's calendar for a free 15-minute consult. He'll walk through your options - whether that's targeted upgrades or budgeting for replacement."</li>
      <li><strong>If service opportunity:</strong> "We can handle [backup setup / security hardening / performance tuning] same-week. Usually takes 45 min - 1 hour remotely."</li>
      <li><strong>If just needs education:</strong> "I can send you our maintenance checklist. If you get stuck on any of it, we're a phone call away."</li>
    </ul>
    
    <h3 style="color: #5b7db1;">CLOSE (Assume the sale):</h3>
    <p><strong>YOU:</strong> "I'm looking at Jeremy's calendar - I have [Day] at [Time] or [Day] at [Time]. Which works better for you?"</p>
    <p style="font-size: 12px; color: #666;"><em>[If they hesitate: "No pressure - what questions can I answer to help you decide?"]</em></p>
    
    <h3 style="color: #d32f2f; margin-top: 20px;">OBJECTION HANDLING:</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold; width: 200px;">"Too expensive"</td>
        <td style="padding: 8px;">"I hear you. Most clients tell us they save 2-3 hours/week after we optimize their setup. What's your time worth per hour? Let's do the math together."</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"I'll do it myself"</td>
        <td style="padding: 8px;">"Totally respect that! Want me to email you our step-by-step guide? If you hit any snags, we're here. No judgment."</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"Need to think about it"</td>
        <td style="padding: 8px;">"Of course. What specific part are you mulling over - the cost, the timing, or something else? Let me address that for you."</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"Just had Apple look at it"</td>
        <td style="padding: 8px;">"Great! What did they recommend? [Listen] We specialize in the stuff Apple doesn't cover - like ${criticalFlags.length > 0 ? criticalFlags[0].clientFacing : 'backup optimization and performance tuning'}. Did they mention that?"</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"It's working fine for me"</td>
        <td style="padding: 8px;">"That's good to hear! The scan flagged a few things that could cause problems down the road - mainly ${criticalFlags.length > 0 ? criticalFlags[0].clientFacing.toLowerCase() : 'preventative stuff'}. Want me to send you a heads-up timeline so you can plan ahead?"</td>
      </tr>
      <tr>
        <td style="padding: 8px; font-weight: bold;">"Can I just buy a new Mac?"</td>
        <td style="padding: 8px;">"Absolutely! That's one of the options Jeremy helps people evaluate. He'll show you what you'd need to spend new vs. what targeted upgrades would cost. Usually saves people $500-1000 if we can extend what you have."</td>
      </tr>
    </table>
    
    <p style="margin-top: 20px; padding: 15px; background: #fff; border-left: 4px solid #5b7db1;"><strong>KEY PRINCIPLE:</strong> You're a consultant, not a salesperson. Your job is to help them make an informed decision - even if that decision is "do nothing." Trust builds repeat business.</p>
  </div>

  <div style="background: #e3f2fd; border-radius: 8px; padding: 20px; margin-top: 20px; text-align: center;">
    <a href="mailto:${clientEmail}" style="display: inline-block; background: #5b7db1; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px;">📧 Reply to Lead</a>
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
    console.log(`System Health: ${analysis.systemHealth}`);
    console.log(`Flags: ${analysis.criticalCount} critical, ${analysis.moderateCount} moderate`);

    // Generate emails
    const clientEmailHTML = generateClientEmail(data, analysis);
    const internalEmailHTML = generateInternalEmail(data, analysis);

    // Send email to CLIENT
    const clientEmailResponse = await resend.emails.send({
      from: 'Velocity Strip-Search <scanner@drwinmac.tech>',
      to: clientEmail,
      subject: '✅ Your Mac Analysis Results',
      html: clientEmailHTML
    });

    // Send email to YOU (Jeremy)
    const internalEmailResponse = await resend.emails.send({
      from: 'Velocity Leads <leads@drwinmac.tech>',
      to: 'Jeremy@drwinmac.tech',
      subject: `🎯 ${analysis.priorityLevel} LEAD: ${clientEmail} - ${analysis.systemHealth} - $${analysis.totalOpportunity}+`,
      html: internalEmailHTML
    });

    console.log('✅ Emails sent successfully');

    res.json({ 
      success: true,
      message: 'Scan results processed and emails sent',
      priority: analysis.priorityLevel,
      systemHealth: analysis.systemHealth,
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
  res.json({ status: 'ok', service: 'velocity-strip-search', version: '2.0' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Velocity Strip-Search Backend running on port ${PORT}`);
  console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? 'CONFIGURED' : 'MISSING API KEY'}`);
  console.log(`💎 Trust > Sales - Honest assessments build real relationships`);
});
